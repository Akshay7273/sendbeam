package engine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// SaveHandoffText writes a verified handoff payload to dir as text.txt/link.txt.
// It is a deliberate receiver action: the frontend only calls it from the
// explicit Save button after the payload verified. The write refuses to
// overwrite an existing file and uses a non-colliding name instead.
func (s *TransferService) SaveHandoffText(kind, content, dir string) (string, error) {
	if kind != wire.ContentKindText && kind != wire.ContentKindLink {
		return "", fmt.Errorf("handoff kind must be %q or %q", wire.ContentKindText, wire.ContentKindLink)
	}
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("destination folder is required")
	}
	if len(content) == 0 || len(content) > wire.MaxHandoffBytes {
		return "", fmt.Errorf("handoff payload must be 1 to %d bytes", wire.MaxHandoffBytes)
	}
	if !utf8.ValidString(content) {
		return "", errors.New("handoff payload is not valid UTF-8")
	}
	base := "text.txt"
	if kind == wire.ContentKindLink {
		base = "link.txt"
	}
	name := strings.TrimSuffix(base, ".txt")
	// Atomic, race-safe create: O_EXCL refuses an existing file, so a
	// colliding process can never be silently overwritten. Exhausting the
	// collision loop is an explicit error, not an overwrite.
	var saved string
	for i := 0; i < 1000; i++ {
		path := filepath.Join(dir, base)
		if i > 0 {
			path = filepath.Join(dir, fmt.Sprintf("%s-%d.txt", name, i))
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", fmt.Errorf("save handoff: %w", err)
		}
		_, werr := f.Write([]byte(content))
		cerr := f.Close()
		if werr != nil {
			return "", fmt.Errorf("save handoff: %w", werr)
		}
		if cerr != nil {
			return "", fmt.Errorf("save handoff: %w", cerr)
		}
		saved = path
		break
	}
	if saved == "" {
		return "", errors.New("save handoff: could not find a free file name")
	}
	return saved, nil
}

// OpenHandoffLink opens a validated http(s) link in the OS default browser.
// It re-validates with the same canonical rules as the transfer receiver
// (net/url, exact http/https scheme, non-empty host): the frontend only calls
// it from the explicit Open button after the payload verified, and nothing is
// ever opened automatically.
func (s *TransferService) OpenHandoffLink(raw string) error {
	// Reuse the canonical handoff validation so the backend enforces exactly
	// what the receiver enforced: no whitespace, http(s) scheme, host present.
	if err := transfer.ValidateHandoffPayload(wire.ContentKindLink, raw); err != nil {
		return fmt.Errorf("open link: %w", err)
	}
	var err error
	switch runtime.GOOS {
	case "darwin":
		err = exec.Command("open", raw).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", raw).Start()
	default:
		err = exec.Command("xdg-open", raw).Start()
	}
	if err != nil {
		return fmt.Errorf("open link: %w", err)
	}
	return nil
}
