// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// seedRetryRecord builds a fully valid sender record (the same identity the
// store's self-check verifies: fingerprint over transfer id + file set),
// then optionally attaches a resume secret. It returns the transfer id for
// the retry lookup.
func seedRetryRecord(t *testing.T, store *transfer.SenderStore, name string, withSecret bool) (id string, secret []byte) {
	t.Helper()
	srcPath := filepath.Join(t.TempDir(), name+".bin")
	if err := os.WriteFile(srcPath, []byte("retry resume payload for "+name), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	sources, total, err := transfer.NewOSFileSources([]string{srcPath})
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	var rawID [16]byte
	if _, err := rand.Read(rawID[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	id = hex.EncodeToString(rawID[:])

	entries := make([]wire.FileEntry, len(sources))
	for i, source := range sources {
		meta := source.Meta()
		entries[i] = wire.FileEntry{
			Idx: i, Name: meta.Name, Size: meta.Size, Mime: meta.Mime,
			LastModified: meta.LastModified, BlockSize: 65536,
			Blocks:     int((meta.Size-1)/65536 + 1),
			FileDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}
	}
	fp, err := wire.ManifestFingerprint(wire.Manifest{TransferID: id, Files: entries, TotalSize: total})
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	files := make([]transfer.SenderFileState, len(entries))
	for i, e := range entries {
		files[i] = transfer.SenderFileState{
			Idx: e.Idx, Name: e.Name, Size: e.Size, Mime: e.Mime,
			LastModified: e.LastModified, BlockSize: e.BlockSize, Blocks: e.Blocks,
			FileDigest: e.FileDigest,
		}
	}
	var env *wire.ResumeSecretEnvelope
	if withSecret {
		secret = bytes.Repeat([]byte{0xA5}, 32)
		env, err = wire.EncodeResumeSecretEnvelope(secret)
		if err != nil {
			t.Fatalf("encode resume secret: %v", err)
		}
	}
	now := time.Now().UnixMilli()
	rec := transfer.SenderRecord{
		// Must track transfer.senderSchemaVersion (unexported); the
		// store rejects records with a wrong schema version.
		SchemaVersion:       2,
		TransferID:          id,
		ManifestFingerprint: fp,
		ProtocolVersion:     wire.ProtocolVersion,
		CreatedAt:           now,
		UpdatedAt:           now,
		Paths:               []string{srcPath},
		Files:               files,
		ResumeSecret:        env,
	}
	if err := store.Save(rec); err != nil {
		t.Fatalf("save sender record: %v", err)
	}
	return id, secret
}

// TestResumeContextForRetry verifies the V21-PR07 retry resume wiring: a
// reused record carrying a resume secret yields an authenticated resume
// context (offerer role, record fingerprint, decoded secret); without a
// secret — or without a record — the send must start fresh (nil).
func TestResumeContextForRetry(t *testing.T) {
	store, err := transfer.OpenSenderStore(t.TempDir())
	if err != nil {
		t.Fatalf("open sender store: %v", err)
	}

	id, secret := seedRetryRecord(t, store, "with-secret", true)
	ctx := resumeContextForRetry(store, id)
	if ctx == nil {
		t.Fatal("expected a resume context for a record carrying a resume secret")
	}
	if ctx.TransferID != id {
		t.Fatalf("wrong transfer id: %q", ctx.TransferID)
	}
	rec, _, _ := store.Load(id)
	if ctx.ManifestFingerprint != rec.ManifestFingerprint {
		t.Fatalf("wrong fingerprint: %q", ctx.ManifestFingerprint)
	}
	if ctx.Role != wire.RoleOfferer {
		t.Fatalf("resume role must be offerer, got %q", ctx.Role)
	}
	if !bytes.Equal(ctx.ResumeSecret, secret) {
		t.Fatal("resume secret did not round-trip through the record")
	}

	id2, _ := seedRetryRecord(t, store, "no-secret", false)
	if ctx := resumeContextForRetry(store, id2); ctx != nil {
		t.Fatal("record without a resume secret must send fresh (nil context)")
	}
	if ctx := resumeContextForRetry(store, "ffffffffffffffffffffffffffffffff"); ctx != nil {
		t.Fatal("unknown transfer id must send fresh (nil context)")
	}
}
