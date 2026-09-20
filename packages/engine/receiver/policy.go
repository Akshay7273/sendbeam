package receiver

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// spaceDecline runs the read-only disk-space preflight for a consent-time
// destination directory. It returns a decline decision when the manifest
// cannot fit, or nil when the transfer may proceed to consent. The check is
// advisory — the full preflight in DurableDestination.Prepare stays the hard
// guarantee — so an unqueryable filesystem never blocks consent here.
func spaceDecline(destDir string, manifest wire.Manifest) *ConsentDecision {
	if err := transfer.PreflightSpaceAvailable(destDir, manifest.TotalSize); err != nil {
		return &ConsentDecision{Accepted: false, Reason: err.Error()}
	}
	return nil
}

// AutoAcceptPolicy is the routine-aware auto-accept policy (V22-PR06):
// narrowly scoped auto-accept for transfers that carry a recipe
// provenance. It is independent of — and narrower than — the legacy
// global AutoAccept flag and per-peer TrustPolicy.AutoAccept, which accept
// ANY transfer from a trusted device. This policy accepts only transfers
// that (a) carry a valid routine provenance, (b) come from an explicitly
// allowlisted sender device, and (c) pass the same trust and tombstone
// validation as every other transfer (that validation runs first, in
// EvaluateConsent, before this policy is consulted).
//
// The zero value is safe: Enabled=false auto-accepts nothing, and an
// empty AllowedDevices list auto-accepts nothing even when enabled.
type AutoAcceptPolicy struct {
	// Enabled is the master switch. Default false: every transfer goes
	// to manual consent unless the user explicitly opts in.
	Enabled bool `json:"enabled"`
	// AllowRoutineTransfers permits provenance-carrying transfers from
	// allowlisted devices to skip the consent prompt. It is separate
	// from Enabled so the policy can be enabled-but-empty (accept
	// nothing) versus disabled entirely.
	AllowRoutineTransfers bool `json:"allowRoutineTransfers"`
	// AllowedDevices is the explicit allowlist of sender device ids
	// whose routine transfers may auto-accept. Empty accepts none.
	AllowedDevices []string `json:"allowedDevices,omitempty"`
}

// ValidateAutoAcceptPolicy checks an auto-accept policy for shape: the
// allowlist entries must be non-empty strings. A nil/empty allowlist is
// valid (it simply accepts nothing). Validation never broadens: doubt
// fails closed to manual consent at evaluation time.
func ValidateAutoAcceptPolicy(p AutoAcceptPolicy) error {
	for i, id := range p.AllowedDevices {
		if id == "" {
			return wire.Errorf(wire.CodeStorage, "receiver: auto-accept policy allowlist entry %d is empty", i)
		}
	}
	return nil
}

// autoAcceptRoutine reports whether the routine auto-accept policy accepts
// this transfer: the policy is enabled, routine transfers are allowed, the
// manifest carries a valid routine provenance, and the peer device is on
// the explicit allowlist. It never errors — any doubt (malformed
// provenance, unlisted sender, disabled policy) falls through to the
// legacy paths and then to manual consent. Trust and tombstone validation
// have already passed before this is consulted.
func autoAcceptRoutine(p AutoAcceptPolicy, peerDeviceID string, manifest wire.Manifest) bool {
	if !p.Enabled || !p.AllowRoutineTransfers {
		return false
	}
	if manifest.Provenance == nil {
		return false
	}
	if err := wire.ValidateProvenance(manifest.Provenance); err != nil {
		return false
	}
	for _, id := range p.AllowedDevices {
		if id != "" && id == peerDeviceID {
			return true
		}
	}
	return false
}

// EvaluateConsent evaluates whether an incoming transfer should be auto-accepted or requires
// user consent, strictly enforcing peer revocation and policy restrictions.
func EvaluateConsent(
	ctx context.Context,
	store trust.Store,
	tombstones trust.TombstoneStore,
	globalAutoAccept bool,
	routinePolicy AutoAcceptPolicy,
	defaultDestDir string,
	peerDeviceID string,
	manifest wire.Manifest,
	handler ConsentHandler,
) (ConsentDecision, error) {
	// 1. Strict Revocation & Trust Enforcement (V19-PR04)
	if tombstones != nil && tombstones.HasTombstone(ctx, peerDeviceID) {
		return ConsentDecision{Accepted: false, Reason: "peer device is revoked"}, wire.ErrTrustedPeerRevoked
	}

	if store == nil {
		return ConsentDecision{Accepted: false, Reason: "trust store not available"}, wire.ErrTrustedPeerMismatch
	}

	dev, err := store.GetDevice(ctx, peerDeviceID)
	if err != nil || dev == nil {
		return ConsentDecision{Accepted: false, Reason: "unrecognized peer device"}, wire.ErrTrustedPeerMismatch
	}

	if dev.Revoked {
		return ConsentDecision{Accepted: false, Reason: "peer device is revoked"}, wire.ErrTrustedPeerRevoked
	}

	// 2. Global Auto-Accept (e.g. CLI --auto-accept flag)
	if globalAutoAccept {
		destDir := defaultDestDir
		if dev.Policy.AutoAcceptDestDir != "" {
			destDir = dev.Policy.AutoAcceptDestDir
		}
		if decline := spaceDecline(destDir, manifest); decline != nil {
			return *decline, nil
		}
		return ConsentDecision{Accepted: true, DestDir: destDir}, nil
	}

	// 3. Peer-Specific Trust Policy (V16-PR04 / V19-PR06)
	if dev.Policy.AutoAccept {
		autoAcceptOK := true

		// Check file size bounds
		if dev.Policy.MaxFileSizeBytes > 0 && manifest.TotalSize > dev.Policy.MaxFileSizeBytes {
			autoAcceptOK = false
		}

		// Check allowed MIME types / extensions
		if autoAcceptOK && len(dev.Policy.AllowedMimeTypes) > 0 {
			for _, file := range manifest.Files {
				if !isMimeAllowed(file.Name, file.Mime, dev.Policy.AllowedMimeTypes) {
					autoAcceptOK = false
					break
				}
			}
		}

		if autoAcceptOK {
			destDir := dev.Policy.AutoAcceptDestDir
			if destDir == "" {
				destDir = defaultDestDir
			}
			if decline := spaceDecline(destDir, manifest); decline != nil {
				return *decline, nil
			}
			return ConsentDecision{Accepted: true, DestDir: destDir}, nil
		}
	}

	// 4. Routine auto-accept (V22-PR06): narrowly scoped to
	// provenance-carrying transfers from explicitly allowlisted sender
	// devices. Trust and tombstone validation already passed above; the
	// legacy broad paths did not accept, so this is strictly narrower
	// than them — it can only accept transfers the broad paths declined
	// to accept automatically. Anything doubtful falls through to manual
	// consent below.
	if autoAcceptRoutine(routinePolicy, dev.DeviceID, manifest) {
		destDir := defaultDestDir
		if dev.Policy.AutoAcceptDestDir != "" {
			destDir = dev.Policy.AutoAcceptDestDir
		}
		if decline := spaceDecline(destDir, manifest); decline != nil {
			return *decline, nil
		}
		return ConsentDecision{Accepted: true, DestDir: destDir}, nil
	}

	// 5. Fall through to explicit user consent prompt. The disk-space
	// preflight runs before prompting: a transfer that cannot fit will
	// fail, so declining fast with the reason beats a doomed prompt.
	if decline := spaceDecline(defaultDestDir, manifest); decline != nil {
		return *decline, nil
	}

	if handler == nil {
		return ConsentDecision{Accepted: false, Reason: "no consent handler configured"}, nil
	}

	req := ConsentRequest{
		TransferID:   manifest.TransferID,
		PeerDeviceID: peerDeviceID,
		PeerLabel:    dev.LocalLabel,
		Files:        manifest.Files,
		TotalSize:    manifest.TotalSize,
		DestDir:      defaultDestDir,
		ContentKind:  manifest.ContentKind,
		// V22-PR06: the routine origin label rides the consent surface so
		// the UI can show where the transfer came from. Nil for ordinary
		// one-off sends; the manifest was wire-validated on decode.
		Provenance: manifest.Provenance,
	}

	return handler(ctx, req)
}

func isMimeAllowed(fileName, mime string, allowed []string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	extWithoutDot := strings.TrimPrefix(ext, ".")
	mime = strings.ToLower(mime)

	for _, pattern := range allowed {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" || pattern == "*" || pattern == "*/*" {
			return true
		}
		if mime != "" && (mime == pattern || strings.HasPrefix(mime, strings.TrimSuffix(pattern, "*"))) {
			return true
		}
		if extWithoutDot != "" && (extWithoutDot == pattern || ext == pattern) {
			return true
		}
	}
	return false
}
