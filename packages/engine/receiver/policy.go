package receiver

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// EvaluateConsent evaluates whether an incoming transfer should be auto-accepted or requires
// user consent, strictly enforcing peer revocation and policy restrictions.
func EvaluateConsent(
	ctx context.Context,
	store trust.Store,
	tombstones trust.TombstoneStore,
	globalAutoAccept bool,
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
			return ConsentDecision{Accepted: true, DestDir: destDir}, nil
		}
	}

	// 4. Fall through to explicit user consent prompt
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
