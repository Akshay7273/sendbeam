// V20-PR06: encrypted text/link handoffs.
//
// A handoff is an ordinary encrypted transfer of one small in-memory payload,
// marked with a contentKind envelope on the wire manifest. The sender builds
// the payload from explicit user input (CLI --text/--link, web composer);
// the receiver captures it into a HandoffDestination instead of the
// destination directory and holds it for deliberate receiver actions
// (Copy/Save/Open) after the transfer verified. The envelope reuses the
// existing consent, encryption, integrity, and session machinery — no
// parallel ad-hoc crypto, no clipboard surveillance, no automatic opening.
package transfer

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/sendbeam/wire"
)

// HandoffFileName is the wire-visible entry name for a handoff payload. An
// older peer that does not understand contentKind saves it under this plain
// name — graceful degradation, never a silent reinterpretation.
func HandoffFileName(kind string) string {
	if kind == wire.ContentKindLink {
		return "link.txt"
	}
	return "text.txt"
}

// ValidateHandoffPayload enforces the handoff payload invariants on either
// side of the wire: kind must be "text" or "link"; the payload must be
// non-empty valid UTF-8 within the handoff byte ceiling; a link must
// additionally be a whitespace-free http(s) URL with a host. The sender runs
// this before starting (via NewTextSource); the receiver runs it again in
// Close, after the whole-set digest verified — the digest proves the sender
// sent these bytes, not that they honor the typed envelope.
func ValidateHandoffPayload(kind, text string) error {
	if !wire.IsHandoffKind(kind) {
		return errors.New("handoff: unknown content kind")
	}
	if !utf8.ValidString(text) {
		return errors.New("handoff: text is not valid UTF-8")
	}
	if len(text) == 0 {
		return errors.New("handoff: text is empty")
	}
	if len(text) > wire.MaxHandoffBytes {
		return errors.New("handoff: text exceeds the 256 KiB handoff ceiling")
	}
	if kind == wire.ContentKindLink {
		if strings.ContainsAny(text, " \t\n\r") {
			return errors.New("handoff: link contains whitespace")
		}
		u, err := url.Parse(text)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("handoff: link must be an http(s) URL")
		}
	}
	return nil
}

// NewTextSource builds a wire.FileSource for an explicit text or link handoff.
// Anything invalid is a caller error, reported before any transfer starts.
func NewTextSource(kind, text string) (wire.FileSource, error) {
	if err := ValidateHandoffPayload(kind, text); err != nil {
		return nil, err
	}
	meta := wire.FileMeta{
		Name: HandoffFileName(kind),
		Size: int64(len(text)),
		Mime: "text/plain; charset=utf-8",
	}
	return wire.BytesSource([]byte(text), meta, 64*1024), nil
}

// HandoffDestination is a wire.Destination that captures one verified handoff
// payload in memory. It never touches the filesystem: no directory is created,
// no partial file is written, and the payload is released to the receiver
// only after the transfer verified (Content, called after Close).
type HandoffDestination struct {
	mu       sync.Mutex
	kind     string
	expected int64
	buf      []byte
	received int64
	opened   bool
	closed   bool
	aborted  bool
}

// NewHandoffDestination builds a destination for the given handoff kind.
func NewHandoffDestination(kind string) *HandoffDestination {
	return &HandoffDestination{kind: kind}
}

// Prepare validates the manifest against the handoff envelope invariants
// (exactly one small payload). The wire receiver already validated the
// manifest; this is defense in depth at the sink boundary.
func (d *HandoffDestination) Prepare(manifest wire.Manifest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !wire.IsHandoffKind(manifest.ContentKind) {
		return errors.New("handoff: manifest is not a handoff envelope")
	}
	if len(manifest.Files) != 1 || manifest.TotalSize <= 0 ||
		manifest.TotalSize > wire.MaxHandoffBytes || manifest.Files[0].Size != manifest.TotalSize {
		return errors.New("handoff: manifest envelope is malformed")
	}
	d.kind = manifest.ContentKind
	d.expected = manifest.TotalSize
	d.buf = make([]byte, 0, manifest.TotalSize)
	return nil
}

// Open hands out the single in-memory sink for the envelope's one file.
func (d *HandoffDestination) Open(file wire.FileEntry) (wire.Sink, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.opened {
		return nil, errors.New("handoff: sink opened more than once")
	}
	d.opened = true
	return &handoffSink{dest: d}, nil
}

// Close marks the destination settled. The wire receiver calls Close only
// after the whole-set digest verified, so content captured here is verified.
// The payload is re-validated against the typed envelope: a sender that marks
// arbitrary or malformed bytes as text/link fails the receive instead of
// handing the receiver something the UI must second-guess.
func (d *HandoffDestination) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.aborted {
		if err := ValidateHandoffPayload(d.kind, string(d.buf)); err != nil {
			d.aborted = true
			d.buf = nil
			return err
		}
	}
	d.closed = true
	return nil
}

// Abort discards the captured payload.
func (d *HandoffDestination) Abort(reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.aborted = true
	d.buf = nil
	return nil
}

// Content returns the verified handoff payload. It is only available after
// Close; before that the transfer has not verified and there is nothing to
// hand to the receiver.
func (d *HandoffDestination) Content() (kind, text string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed || d.aborted {
		return "", "", errors.New("handoff: content is not available before verified completion")
	}
	return d.kind, string(d.buf), nil
}

type handoffSink struct {
	dest *HandoffDestination
}

// Write appends verified blocks in order. The receiver only ever writes
// blocks whose per-block hash already verified, so the buffer holds verified
// bytes; the in-order and ceiling checks below are structural guards.
func (s *handoffSink) Write(offset int64, p []byte) error {
	d := s.dest
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.aborted {
		return errors.New("handoff: write after abort")
	}
	if offset != d.received {
		return errors.New("handoff: out-of-order write")
	}
	if d.received+int64(len(p)) > d.expected {
		return errors.New("handoff: write exceeds the advertised payload size")
	}
	d.buf = append(d.buf, p...)
	d.received += int64(len(p))
	return nil
}

func (s *handoffSink) Close() error { return nil }

func (s *handoffSink) Abort(reason string) error {
	return s.dest.Abort(reason)
}

// HandoffKindOf reports the manifest's handoff kind, or "" for file sets.
func HandoffKindOf(manifest wire.Manifest) string {
	if wire.IsHandoffKind(manifest.ContentKind) {
		return manifest.ContentKind
	}
	return ""
}

// IsHandoffManifest reports whether the manifest is a handoff envelope.
func IsHandoffManifest(manifest wire.Manifest) bool { return HandoffKindOf(manifest) != "" }

// PreviewText renders the inert receiver preview: literal text, truncated,
// with no markup, no linkification, and no clipboard interaction. The UI must
// render the returned string as plain text only.
func PreviewText(text string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 400
	}
	runes := []rune(text)
	if len(runes) <= maxRunes {
		return strings.TrimSpace(text)
	}
	return strings.TrimSpace(string(runes[:maxRunes])) + "…"
}
