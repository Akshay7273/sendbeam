package transfer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

func TestPaddedTransferEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := bytes.Repeat([]byte("super secret private padded payload"), 1000) // 35 KB
	meta := wire.FileMeta{
		Name:         "secret.txt",
		Size:         int64(len(content)),
		Mime:         "text/plain",
		LastModified: 1_700_000_000_000,
	}
	src := wire.BytesSource(content, meta, 16*1024)

	relayServer := newRelay()

	type res struct {
		outcome *Outcome
		err     error
	}
	offCh := make(chan res, 1)
	joinCh := make(chan res, 1)

	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     src,
			ICEServers: []webrtc.ICEServer{},
			Private:    true,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    destDir,
			ICEServers: []webrtc.ICEServer{},
			Private:    true,
		})
		joinCh <- res{o, err}
	}()

	offRes := <-offCh
	joinRes := <-joinCh

	if offRes.err != nil {
		t.Fatalf("offerer error: %v", offRes.err)
	}
	if joinRes.err != nil {
		t.Fatalf("joiner error: %v", joinRes.err)
	}

	if offRes.outcome.Digest != joinRes.outcome.Digest {
		t.Fatalf("digest mismatch: offerer %s vs joiner %s", offRes.outcome.Digest, joinRes.outcome.Digest)
	}

	received, err := os.ReadFile(filepath.Join(destDir, "secret.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("received content mismatch")
	}
}

func TestPaddedTransferFallbackWithLegacyPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := []byte("interoperability test with unpadded peer")
	meta := wire.FileMeta{
		Name:         "interop.txt",
		Size:         int64(len(content)),
		Mime:         "text/plain",
		LastModified: 1_700_000_000_000,
	}
	src := wire.BytesSource(content, meta, 16*1024)

	relayServer := newRelay()

	type res struct {
		outcome *Outcome
		err     error
	}
	offCh := make(chan res, 1)
	joinCh := make(chan res, 1)

	// Offerer requests Private (padding), but joiner is unpadded (Private: false)
	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     src,
			ICEServers: []webrtc.ICEServer{},
			Private:    true,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    destDir,
			ICEServers: []webrtc.ICEServer{},
			Private:    false,
		})
		joinCh <- res{o, err}
	}()

	offRes := <-offCh
	joinRes := <-joinCh

	if offRes.err != nil {
		t.Fatalf("offerer error: %v", offRes.err)
	}
	if joinRes.err != nil {
		t.Fatalf("joiner error: %v", joinRes.err)
	}

	if offRes.outcome.Digest != joinRes.outcome.Digest {
		t.Fatalf("digest mismatch: offerer %s vs joiner %s", offRes.outcome.Digest, joinRes.outcome.Digest)
	}

	received, err := os.ReadFile(filepath.Join(destDir, "interop.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("received content mismatch")
	}
}

func TestRelayPaddedTransferWithJitter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := bytes.Repeat([]byte("confidential payload over relay with padding and jitter"), 500)
	meta := wire.FileMeta{
		Name:         "relay_jitter.txt",
		Size:         int64(len(content)),
		Mime:         "text/plain",
		LastModified: 1_700_000_000_000,
	}
	src := wire.BytesSource(content, meta, 16*1024)

	relayServer := newRelay()

	type res struct {
		outcome *Outcome
		err     error
	}
	offCh := make(chan res, 1)
	joinCh := make(chan res, 1)

	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      src,
			ForceRelay:  true,
			Private:     true,
			RelayJitter: 10 * time.Millisecond,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    destDir,
			ForceRelay: true,
			Private:    true,
		})
		joinCh <- res{o, err}
	}()

	offRes := <-offCh
	joinRes := <-joinCh

	if offRes.err != nil {
		t.Fatalf("offerer error: %v", offRes.err)
	}
	if joinRes.err != nil {
		t.Fatalf("joiner error: %v", joinRes.err)
	}

	if offRes.outcome.Digest != joinRes.outcome.Digest {
		t.Fatalf("digest mismatch: offerer %s vs joiner %s", offRes.outcome.Digest, joinRes.outcome.Digest)
	}

	received, err := os.ReadFile(filepath.Join(destDir, "relay_jitter.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("received content mismatch")
	}
}
