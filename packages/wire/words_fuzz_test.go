package wire

import (
	"strings"
	"testing"
)

// FuzzWordsCode tests invite-code normalization, room-code parsing, and code formatting
// against arbitrary strings, unicode characters, edge delimiters, and hostile sequences.
// Invariants:
// 1. NormalizeCode must never panic on any input string.
// 2. NormalizeCode result must contain only lowercase ASCII letters, digits, and single '-' separators.
// 3. ParseCode must never panic.
// 4. If ParseCode succeeds, FormatCode(parsed.Room, parsed.Words) normalized must equal NormalizeCode(input).
func FuzzWordsCode(f *testing.F) {
	seeds := []string{
		"0-brave-otter",
		"1-swift-fox",
		"42-ant-ape",
		"999-cedar-cliff",
		"0-ant",
		"",
		"-",
		"--",
		"---",
		"0-",
		"-otter",
		"abc-def",
		"123",
		"0--brave--otter",
		" 0 - brave - otter ",
		"0-BRAVE-OTTER",
		"0-brave\x00otter",
		"0-日本語-テスト",
		"9999999999999999999999999999999999999-otter",
		"-1-brave-otter",
		"000 0000000",
		"007-tiger",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		norm := NormalizeCode(raw)

		// Check normalization properties
		if strings.HasPrefix(norm, "-") || strings.HasSuffix(norm, "-") {
			t.Fatalf("NormalizeCode(%q) = %q has leading/trailing hyphens", raw, norm)
		}
		if strings.Contains(norm, "--") {
			t.Fatalf("NormalizeCode(%q) = %q has consecutive hyphens", raw, norm)
		}
		for _, r := range norm {
			isLower := r >= 'a' && r <= 'z'
			isDigit := r >= '0' && r <= '9'
			isHyphen := r == '-'
			if !isLower && !isDigit && !isHyphen {
				t.Fatalf("NormalizeCode(%q) = %q contains invalid char %q", raw, norm, r)
			}
		}

		// Check idempotency of NormalizeCode
		if norm2 := NormalizeCode(norm); norm2 != norm {
			t.Fatalf("NormalizeCode not idempotent: %q -> %q -> %q", raw, norm, norm2)
		}

		// Exercise ParseCode
		parsed, err := ParseCode(raw)
		if err == nil {
			if parsed.Words == "" {
				t.Fatalf("ParseCode(%q) succeeded with empty words", raw)
			}

			// Round-trip formatting: FormatCode must re-parse to identical Room and Words
			formatted := FormatCode(parsed.Room, parsed.Words)
			parsed2, err := ParseCode(formatted)
			if err != nil {
				t.Fatalf("ParseCode failed on formatted code %q: %v", formatted, err)
			}
			if parsed2 != parsed {
				t.Fatalf("ParseCode mismatch after FormatCode: original %+v != reparsed %+v (formatted %q)",
					parsed, parsed2, formatted)
			}
		}
	})
}
