package engine_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDesktopFrontend_LiteralTextRendering verifies that the embedded desktop
// HTML shell never uses innerHTML, outerHTML, document.write, or other unsafe
// DOM sinks, ensuring untrusted remote data (paths, errors, identities) is rendered
// strictly as literal text.
func TestDesktopFrontend_LiteralTextRendering(t *testing.T) {
	path := filepath.Join("..", "..", "frontend", "dist", "index.html")
	contentBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read desktop index.html at %s: %v", path, err)
	}
	content := string(contentBytes)
	if len(content) == 0 {
		t.Fatal("desktop index.html is empty")
	}

	prohibitedSinks := []struct {
		pattern string
		reason  string
	}{
		{"innerHTML", "must not use innerHTML; use textContent, createTextNode, or replaceChildren"},
		{"outerHTML", "must not use outerHTML"},
		{"document.write", "must not use document.write"},
		{"insertAdjacentHTML", "must not use insertAdjacentHTML"},
		{"javascript:", "must not contain javascript: pseudo-protocol"},
		{"vbscript:", "must not contain vbscript: pseudo-protocol"},
	}

	for _, tc := range prohibitedSinks {
		if strings.Contains(content, tc.pattern) {
			t.Errorf("desktop index.html contains forbidden pattern %q: %s", tc.pattern, tc.reason)
		}
	}

	requiredConstructs := []struct {
		pattern string
		desc    string
	}{
		{"setStatusMessage", "safe literal-text status helper"},
		{"renderChips", "safe literal-text chips helper"},
		{"replaceChildren", "safe DOM child clearing"},
		{"textContent", "literal text assignment"},
	}

	for _, req := range requiredConstructs {
		if !strings.Contains(content, req.pattern) {
			t.Errorf("desktop index.html missing required safe rendering construct %q (%s)", req.pattern, req.desc)
		}
	}
}

// TestDesktopFrontend_NoInlineEventHandlers ensures HTML tags do not declare
// inline on* handlers (which could be targeted or set bad precedent).
func TestDesktopFrontend_NoInlineEventHandlers(t *testing.T) {
	path := filepath.Join("..", "..", "frontend", "dist", "index.html")
	contentBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read desktop index.html: %v", err)
	}
	content := string(contentBytes)

	// Split HTML before <script> tag to check markup only
	scriptIdx := strings.Index(content, "<script>")
	if scriptIdx == -1 {
		t.Fatal("no <script> tag found in desktop index.html")
	}
	markup := content[:scriptIdx]

	inlineHandlerRe := regexp.MustCompile(`(?i)\s+on[a-z]+\s*=`)
	if matches := inlineHandlerRe.FindAllString(markup, -1); len(matches) > 0 {
		t.Errorf("found inline event handlers in markup: %v", matches)
	}
}
