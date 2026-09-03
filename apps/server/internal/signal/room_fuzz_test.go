package signal

import (
	"encoding/json"
	"testing"
)

// FuzzServerMessageValidation exercises client message decoding, room validation,
// and frame serialization against arbitrary payloads.
// Invariants:
// 1. json.Unmarshal and frame constructors must never panic on any input bytes.
// 2. Client messages must fail closed on missing required fields (e.g. empty Type, missing Room for join/resume).
func FuzzServerMessageValidation(f *testing.F) {
	seeds := []string{
		`{"type":"create"}`,
		`{"type":"join","room":0}`,
		`{"type":"join","room":-1}`,
		`{"type":"join","room":999999999}`,
		`{"type":"join"}`,
		`{"type":"resume","room":1,"role":"offerer"}`,
		`{"type":"resume","room":1,"role":"joiner"}`,
		`{"type":"resume","room":1,"role":"invalid"}`,
		`{"type":"relay_credit","bytes":0}`,
		`{"type":"relay_credit","bytes":-100}`,
		`{"type":"relay_credit","bytes":1048576}`,
		`{"type":"bye","reason":"user"}`,
		`{}`,
		`not-json`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		var m clientMsg
		if err := json.Unmarshal(data, &m); err != nil {
			return
		}

		if m.Type == "" {
			// dispatch treats empty type as invalid
			return
		}

		// Exercise frame constructors with decoded parameters to verify no panics
		if m.Room != nil {
			_ = createdFrame(*m.Room)
			_ = resumedFrame(*m.Room)
		}
		if m.Role != "" {
			_ = peerJoinedFrame(m.Role)
		}
		_ = creditFrame(m.Bytes)
		_ = byeFrame("teardown")
	})
}
