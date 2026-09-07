package transfer

import (
	"bytes"
	"context"
	"errors"
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

func TestRequirePaddingRejectsUnpaddedPeerSender(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := []byte("secret payload requiring padding")
	meta := wire.FileMeta{
		Name:         "strict_padding_sender.txt",
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

	// Offerer enforces RequirePadding; joiner has padding disabled (Private: false)
	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "strict-sender"},
			Source:         src,
			ICEServers:     []webrtc.ICEServer{},
			RequirePadding: true,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-strict-sender"},
			DestDir:    destDir,
			ICEServers: []webrtc.ICEServer{},
			Private:    false,
		})
		joinCh <- res{o, err}
	}()

	offRes := <-offCh
	cancel()
	joinRes := <-joinCh

	// Sender with RequirePadding MUST fail closed with wire.ErrPaddingRequired
	if offRes.err == nil {
		t.Fatalf("expected offerer to fail closed on incompatible peer, got success")
	}
	if !errors.Is(offRes.err, wire.ErrPaddingRequired) && wire.CodeOf(offRes.err) != wire.CodeCompat {
		t.Fatalf("expected CodeCompat/ErrPaddingRequired, got: %v", offRes.err)
	}

	// Destination file must NOT be written
	if _, err := os.Stat(filepath.Join(destDir, "strict_padding_sender.txt")); !os.IsNotExist(err) {
		t.Fatalf("payload file was created despite require-padding policy failure")
	}
	_ = joinRes
}

func TestRequirePaddingRejectsUnpaddedPeerReceiver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := []byte("secret payload requiring receiver padding")
	meta := wire.FileMeta{
		Name:         "strict_padding_receiver.txt",
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

	// Offerer has padding disabled; joiner enforces RequirePadding
	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "strict-receiver"},
			Source:     src,
			ICEServers: []webrtc.ICEServer{},
			Private:    false,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-strict-receiver"},
			DestDir:        destDir,
			ICEServers:     []webrtc.ICEServer{},
			RequirePadding: true,
		})
		joinCh <- res{o, err}
	}()

	joinRes := <-joinCh
	cancel()
	offRes := <-offCh

	// Receiver with RequirePadding MUST fail closed with wire.ErrPaddingRequired
	if joinRes.err == nil {
		t.Fatalf("expected joiner to fail closed on incompatible peer, got success")
	}
	if !errors.Is(joinRes.err, wire.ErrPaddingRequired) && wire.CodeOf(joinRes.err) != wire.CodeCompat {
		t.Fatalf("expected CodeCompat/ErrPaddingRequired, got: %v", joinRes.err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "strict_padding_receiver.txt")); !os.IsNotExist(err) {
		t.Fatalf("payload file was created despite require-padding policy failure")
	}
	_ = offRes
}

func TestRequirePaddingMutualSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	destDir := t.TempDir()
	content := bytes.Repeat([]byte("confidential payload with mutual require-padding policy active"), 50)
	meta := wire.FileMeta{
		Name:         "strict_padding_success.txt",
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

	// Both offerer and joiner enforce RequirePadding
	go func() {
		o, err := Run(ctx, relayServer.off, Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "strict-mutual"},
			Source:         src,
			ICEServers:     []webrtc.ICEServer{},
			RequirePadding: true,
		})
		offCh <- res{o, err}
	}()
	go func() {
		o, err := Run(ctx, relayServer.join, Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-strict-mutual"},
			DestDir:        destDir,
			ICEServers:     []webrtc.ICEServer{},
			RequirePadding: true,
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

	received, err := os.ReadFile(filepath.Join(destDir, "strict_padding_success.txt"))
	if err != nil {
		t.Fatalf("read received file: %v", err)
	}
	if !bytes.Equal(received, content) {
		t.Fatalf("received content mismatch")
	}
}
