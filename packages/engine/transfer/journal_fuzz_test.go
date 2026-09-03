package transfer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sendbeam/wire"
)

// FuzzDurableJournalApply exercises the ADR-0004 durable journal ingestion path in the engine.
// Invariants:
// 1. Loading corrupt, torn, or mutated journal data must fail closed and never panic.
// 2. Corrupted journal files on disk must never be deleted or partially applied by load operations.
// 3. Any journal that passes LoadJournal must produce a consistent inspect summary.
func FuzzDurableJournalApply(f *testing.F) {
	// Baseline programmatic seeds
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Add([]byte(`{"schemaVersion":1,"transferId":"0123456789abcdef0123456789abcdef"}`))

	// Load seeds from durable-journal.json vector
	for _, path := range []string{"../../../docs/test-vectors/durable-journal.json", "docs/test-vectors/durable-journal.json"} {
		if data, err := os.ReadFile(path); err == nil {
			var doc struct {
				Journal           string `json:"journal"`
				JournalWithSecret string `json:"journalWithSecret"`
			}
			if err := json.Unmarshal(data, &doc); err == nil {
				if doc.Journal != "" {
					f.Add([]byte(doc.Journal))
					if len(doc.Journal) > 20 {
						f.Add([]byte(doc.Journal[:len(doc.Journal)/2]))
						f.Add([]byte(doc.Journal[:len(doc.Journal)-4]))
					}
				}
				if doc.JournalWithSecret != "" {
					f.Add([]byte(doc.JournalWithSecret))
				}
			}
			break
		}
	}

	f.Fuzz(func(t *testing.T, journalData []byte) {
		tmpDir := t.TempDir()
		store, err := OpenStore(tmpDir)
		if err != nil {
			t.Fatalf("OpenStore failed: %v", err)
		}

		transferID := "0123456789abcdef0123456789abcdef"
		jPath := store.JournalPath(transferID)

		if err := os.MkdirAll(filepath.Dir(jPath), 0700); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(jPath, journalData, 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		j, ok, loadErr := store.LoadJournal(transferID)
		if loadErr != nil {
			// Fail-closed invariant: on load error, file must NOT be deleted
			afterData, readErr := os.ReadFile(jPath)
			if readErr != nil {
				t.Fatalf("journal file was removed on load error: %v", readErr)
			}
			if !bytes.Equal(afterData, journalData) {
				t.Fatalf("journal file was modified on load error")
			}
			return
		}

		if !ok {
			// File should have existed since we wrote it
			t.Fatalf("LoadJournal returned ok=false for existing written journal")
		}

		// If LoadJournal succeeded, Inspect must succeed without panic
		info, inspectErr := store.Inspect(transferID)
		if inspectErr != nil {
			t.Fatalf("Inspect failed for successfully loaded journal: %v", inspectErr)
		}
		if info.Journal.TransferID != j.TransferID {
			t.Fatalf("Inspect transferID mismatch: %q != %q", info.Journal.TransferID, j.TransferID)
		}

		// Destination Prepare must not panic
		dest, destErr := NewDurableDestination(tmpDir)
		if destErr == nil {
			dest.ExpectResume(transferID)
			dest.SetResumeAuthorized()
			_ = dest.Prepare(wire.Manifest{
				TransferID: transferID,
				Files: []wire.FileEntry{
					{Idx: 0, Name: "file.txt", Size: 1024, BlockSize: 1024, Blocks: 1},
				},
				TotalSize: 1024,
			})
		}
	})
}
