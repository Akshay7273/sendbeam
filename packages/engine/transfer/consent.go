package transfer

import (
	"context"
	"sync"

	"github.com/sendbeam/wire"
)

// ConsentRequest carries the incoming transfer manifest and peer identity for a consent decision.
type ConsentRequest struct {
	TransferID   string           `json:"transferId"`
	PeerDeviceID string           `json:"peerDeviceId"`
	PeerLabel    string           `json:"peerLabel"`
	Files        []wire.FileEntry `json:"files"`
	TotalSize    int64            `json:"totalSize"`
	DestDir      string           `json:"destDir"`
	// ContentKind is "" for ordinary file transfers and "text"/"link" for an
	// encrypted handoff envelope (V20-PR06): the consent UI must show an inert
	// preview and offer Copy/Save/Open instead of a destination directory.
	ContentKind string `json:"contentKind,omitempty"`
}

// ConsentDecision reports the user or policy acceptance decision for an incoming transfer.
type ConsentDecision struct {
	Accepted bool   `json:"accepted"`
	DestDir  string `json:"destDir,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// ConsentHandler evaluates or prompts for consent for an incoming transfer.
type ConsentHandler func(ctx context.Context, req ConsentRequest) (ConsentDecision, error)

// consentDestination delays DurableDestination creation until consent has been evaluated and
// approved upon manifest arrival. If consent is declined, no directory or file is touched on disk.
type consentDestination struct {
	ctx          context.Context
	specDestDir  string
	consent      ConsentHandler
	peerDeviceID string
	peerLabel    string
	resumeCtx    *ResumeContext

	mu               sync.Mutex
	actual           *DurableDestination
	handoff          *HandoffDestination
	resumeAuthorized bool
	targetDestDir    string
}

func (c *consentDestination) ExpectResume(transferID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.actual != nil {
		c.actual.ExpectResume(transferID)
	}
}

func (c *consentDestination) SetResumeAuthorized() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resumeAuthorized = true
	if c.actual != nil {
		c.actual.SetResumeAuthorized()
	}
}

func (c *consentDestination) Prepare(manifest wire.Manifest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	targetDir := c.specDestDir
	if c.consent != nil {
		req := ConsentRequest{
			TransferID:   manifest.TransferID,
			PeerDeviceID: c.peerDeviceID,
			PeerLabel:    c.peerLabel,
			Files:        manifest.Files,
			TotalSize:    manifest.TotalSize,
			DestDir:      targetDir,
			ContentKind:  HandoffKindOf(manifest),
		}
		decision, err := c.consent(c.ctx, req)
		if err != nil {
			return wire.Errorf(wire.CodeAuth, "transfer consent error: %v", err)
		}
		if !decision.Accepted {
			reason := decision.Reason
			if reason == "" {
				reason = "transfer declined by user"
			}
			return wire.NewTransferError(wire.FailCanceled, reason)
		}
		if decision.DestDir != "" {
			targetDir = decision.DestDir
		}
	}

	// V20-PR06: a handoff envelope is captured in memory, never written to the
	// destination directory. It does not participate in resume: the envelope is
	// small enough that a fresh re-send is the recovery path.
	if IsHandoffManifest(manifest) {
		handoff := NewHandoffDestination(manifest.ContentKind)
		if err := handoff.Prepare(manifest); err != nil {
			return err
		}
		c.handoff = handoff
		return nil
	}

	actual, err := NewDurableDestination(targetDir)
	if err != nil {
		return wire.NewTransferError(wire.FailSinkError, err.Error())
	}
	if c.resumeCtx != nil {
		actual.ExpectResume(c.resumeCtx.TransferID)
	}
	if c.resumeAuthorized {
		actual.SetResumeAuthorized()
	}

	if err := actual.Prepare(manifest); err != nil {
		return err
	}

	c.actual = actual
	c.targetDestDir = targetDir
	return nil
}

func (c *consentDestination) Open(file wire.FileEntry) (wire.Sink, error) {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	if handoff != nil {
		return handoff.Open(file)
	}
	if actual == nil {
		return nil, wire.NewTransferError(wire.FailSinkError, "destination not prepared")
	}
	return actual.Open(file)
}

func (c *consentDestination) Close() error {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	if handoff != nil {
		return handoff.Close()
	}
	if actual == nil {
		return nil
	}
	return actual.Close()
}

func (c *consentDestination) Abort(reason string) error {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	if handoff != nil {
		return handoff.Abort(reason)
	}
	if actual == nil {
		return nil
	}
	return actual.Abort(reason)
}

// HandoffContent returns the verified handoff payload when the prepared
// destination was a handoff envelope, or an error otherwise. Call only after
// the transfer completed: Content is available only after Close.
func (c *consentDestination) HandoffContent() (kind, text string, err error) {
	c.mu.Lock()
	handoff := c.handoff
	c.mu.Unlock()
	if handoff == nil {
		return "", "", wire.NewTransferError(wire.FailSinkError, "transfer was not a handoff")
	}
	return handoff.Content()
}

func (c *consentDestination) ResumeStateFor(manifest wire.Manifest) (*wire.ReceiverResume, error) {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	// V20-PR06: handoffs never resume; a re-send is the recovery path.
	if handoff != nil {
		return nil, nil
	}
	if actual == nil {
		return nil, nil
	}
	return actual.ResumeStateFor(manifest)
}

func (c *consentDestination) AttachResumeSecret(manifest wire.Manifest, resumeRoot []byte) error {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	if handoff != nil {
		return nil
	}
	if actual == nil {
		return nil
	}
	return actual.AttachResumeSecret(manifest, resumeRoot)
}

func (c *consentDestination) Path(fileIdx int) string {
	c.mu.Lock()
	actual := c.actual
	handoff := c.handoff
	c.mu.Unlock()
	// V20-PR06: a handoff has no on-disk path.
	if handoff != nil {
		return ""
	}
	if actual == nil {
		return ""
	}
	return actual.Path(fileIdx)
}
