package receiver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// loopbackSignal couples two endpoints in-memory for testing
type loopbackRelay struct {
	mu            sync.Mutex
	createdHandle string
	created       chan struct{}
	once          sync.Once
	off           *loopbackEnd
	join          *loopbackEnd
}

func newLoopbackRelay() *loopbackRelay {
	r := &loopbackRelay{
		created: make(chan struct{}),
	}
	r.off = &loopbackEnd{hub: r, role: "offerer", in: make(chan rendezvous.Message, 100), bin: make(chan []byte, 100), done: make(chan struct{})}
	r.join = &loopbackEnd{hub: r, role: "joiner", in: make(chan rendezvous.Message, 100), bin: make(chan []byte, 100), done: make(chan struct{})}
	return r
}

func (r *loopbackRelay) partner(e *loopbackEnd) *loopbackEnd {
	if e == r.off {
		return r.join
	}
	return r.off
}

func (r *loopbackRelay) route(from *loopbackEnd, m rendezvous.Message) {
	switch m.Type {
	case "rendezvous":
		r.mu.Lock()
		if r.createdHandle == "" {
			r.createdHandle = m.Handle
			r.mu.Unlock()
			from.enqueue(rendezvous.Message{Type: "created", Handle: m.Handle})
			r.once.Do(func() { close(r.created) })
		} else {
			r.mu.Unlock()
			<-r.created
			r.join.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.join.role})
			r.off.enqueue(rendezvous.Message{Type: "peer-joined", Role: r.off.role})
		}
	case rendezvous.TypeRelayOpen:
		r.mu.Lock()
		from.relayOpen = true
		other := r.partner(from)
		ready := other.relayOpen
		r.mu.Unlock()
		if ready {
			from.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayReady})
		} else {
			other.enqueue(rendezvous.Message{Type: rendezvous.TypeRelayRequired})
		}
	case rendezvous.TypeRelayCredit:
		r.partner(from).enqueue(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: m.Bytes})
	default:
		r.partner(from).enqueue(m)
	}
}

type loopbackEnd struct {
	hub       *loopbackRelay
	role      string
	in        chan rendezvous.Message
	bin       chan []byte
	relayOpen bool
	once      sync.Once
	done      chan struct{}
}

func (e *loopbackEnd) Send(m rendezvous.Message) error {
	e.hub.route(e, m)
	return nil
}

func (e *loopbackEnd) SendBinary(frame []byte) error {
	e.hub.partner(e).enqueueBinary(frame)
	return nil
}

func (e *loopbackEnd) Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error {
	for {
		select {
		case m := <-e.in:
			onMessage(m)
		case frame := <-e.bin:
			onBinary(frame)
		case <-e.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (e *loopbackEnd) Close() {
	e.once.Do(func() { close(e.done) })
}

func (e *loopbackEnd) enqueue(m rendezvous.Message) {
	select {
	case e.in <- m:
	case <-e.done:
	}
}

func (e *loopbackEnd) enqueueBinary(frame []byte) {
	select {
	case e.bin <- append([]byte(nil), frame...):
	case <-e.done:
	}
}

// Helper to setup paired identities in test stores
func setupPairedPeers(t *testing.T, tmpDir string) (idAlice, idBob *wire.DeviceIdentity, kPair []byte, storeBob trust.Store, secretsBob trust.CredentialStore, tombstonesBob trust.TombstoneStore) {
	t.Helper()

	var err error
	idAlice, err = wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	idBob, err = wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	kPair = bytes.Repeat([]byte{0x55}, 32)

	trustPath := filepath.Join(tmpDir, "trust.json")
	storeBob, err = trust.NewFileTrustStore(trustPath)
	if err != nil {
		t.Fatal(err)
	}

	memSecrets := trust.NewMemoryCredentialStore()
	err = memSecrets.SetPairSecret(context.Background(), idAlice.DeviceID, "cred-alice", kPair)
	if err != nil {
		t.Fatal(err)
	}
	secretsBob = memSecrets

	tombstonesPath := filepath.Join(tmpDir, "tombstones.json")
	tombstonesBob, err = trust.NewFileTombstoneStore(tombstonesPath)
	if err != nil {
		t.Fatal(err)
	}

	// Register Alice in Bob's trust store
	recAlice := &wire.TrustRecord{
		DeviceID:          idAlice.DeviceID,
		PublicKey:         idAlice.PublicKeyHex(),
		LocalLabel:        "Alice's Laptop",
		PairCredentialRef: "cred-alice",
		FirstSeenAt:       time.Now().UTC(),
		LastSeenAt:        time.Now().UTC(),
	}
	err = storeBob.AddOrUpdateDevice(context.Background(), recAlice)
	if err != nil {
		t.Fatal(err)
	}

	return idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob
}

func TestReceiverPolicyAutoAccept(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "downloads")
	_ = os.MkdirAll(destDir, 0700)

	idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Update Alice's policy in Bob's store: AutoAccept enabled with max 1MB
	policy := wire.TrustPolicy{
		AutoAccept:        true,
		MaxFileSizeBytes:  1024 * 1024,
		AutoAcceptDestDir: destDir,
	}
	if err := storeBob.UpdatePolicy(context.Background(), idAlice.DeviceID, policy); err != nil {
		t.Fatal(err)
	}

	relay := newLoopbackRelay()

	listener, err := NewListener(Config{
		DestDir:    destDir,
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
		Dialer: func(_ context.Context, _ string) (transfer.Signal, error) {
			return relay.join, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	payload := []byte("auto-accepted file content")
	meta := wire.FileMeta{
		Name:         "doc.txt",
		Size:         int64(len(payload)),
		Mime:         "text/plain",
		LastModified: 1_700_000_000_000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		out *transfer.Outcome
		err error
	}
	sendCh := make(chan result, 1)
	recvCh := make(chan result, 1)

	// Offerer (Alice)
	go func() {
		out, err := transfer.Run(ctx, relay.off, transfer.Spec{
			Opaque: &rendezvous.OpaqueOptions{
				Role:              rendezvous.RoleOfferer,
				Handle:            handle,
				LocalIdentity:     idAlice,
				PeerDeviceID:      idBob.DeviceID,
				PeerPublicKey:     idBob.PublicKey,
				KPair:             kPair,
				PairCredentialRef: "cred-alice",
			},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		sendCh <- result{out, err}
	}()

	// Joiner (Bob)
	go func() {
		out, err := listener.HandleIncomingSession(ctx, relay.join, idAlice.DeviceID, handle)
		recvCh <- result{out, err}
	}()

	send := <-sendCh
	recv := <-recvCh

	if recv.err != nil {
		t.Fatalf("receiver err: %v", recv.err)
	}
	if send.err != nil {
		t.Fatalf("sender err: %v", send.err)
	}

	if send.out.Digest != recv.out.Digest {
		t.Fatalf("digest mismatch: %s vs %s", send.out.Digest, recv.out.Digest)
	}
	if listener.VerifiedDeliveries() != 1 {
		t.Fatalf("verified count = %d, want 1", listener.VerifiedDeliveries())
	}

	got, err := os.ReadFile(recv.out.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %q, want %q", got, payload)
	}
}

func TestReceiverConsentPromptAccept(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "received")

	idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	relay := newLoopbackRelay()

	promptCalled := false
	listener, err := NewListener(Config{
		DestDir:    destDir,
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
		ConsentHandler: func(_ context.Context, req ConsentRequest) (ConsentDecision, error) {
			promptCalled = true
			if req.PeerDeviceID != idAlice.DeviceID {
				t.Errorf("prompt PeerDeviceID = %q, want %q", req.PeerDeviceID, idAlice.DeviceID)
			}
			if len(req.Files) != 1 || req.Files[0].Name != "photo.jpg" {
				t.Errorf("prompt files = %+v", req.Files)
			}
			return ConsentDecision{Accepted: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	payload := []byte("image bytes for photo")
	meta := wire.FileMeta{
		Name:         "photo.jpg",
		Size:         int64(len(payload)),
		Mime:         "image/jpeg",
		LastModified: 1_700_000_000_000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		out *transfer.Outcome
		err error
	}
	sendCh := make(chan result, 1)
	recvCh := make(chan result, 1)

	go func() {
		out, err := transfer.Run(ctx, relay.off, transfer.Spec{
			Opaque: &rendezvous.OpaqueOptions{
				Role:              rendezvous.RoleOfferer,
				Handle:            handle,
				LocalIdentity:     idAlice,
				PeerDeviceID:      idBob.DeviceID,
				PeerPublicKey:     idBob.PublicKey,
				KPair:             kPair,
				PairCredentialRef: "cred-alice",
			},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		sendCh <- result{out, err}
	}()

	go func() {
		out, err := listener.HandleIncomingSession(ctx, relay.join, idAlice.DeviceID, handle)
		recvCh <- result{out, err}
	}()

	send := <-sendCh
	recv := <-recvCh

	if recv.err != nil {
		t.Fatalf("receiver err: %v", recv.err)
	}
	if send.err != nil {
		t.Fatalf("sender err: %v", send.err)
	}
	if !promptCalled {
		t.Fatal("consent prompt was not invoked")
	}
	if send.out.Digest != recv.out.Digest {
		t.Fatalf("digest mismatch: %s vs %s", send.out.Digest, recv.out.Digest)
	}

	got, err := os.ReadFile(recv.out.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %q, want %q", got, payload)
	}
}

func TestReceiverConsentPromptDecline(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "declined_dest")

	idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	relay := newLoopbackRelay()

	listener, err := NewListener(Config{
		DestDir:    destDir,
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
		ConsentHandler: func(_ context.Context, _ ConsentRequest) (ConsentDecision, error) {
			return ConsentDecision{Accepted: false, Reason: "declined by user"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	payload := []byte("super secret data")
	meta := wire.FileMeta{
		Name:         "secret.key",
		Size:         int64(len(payload)),
		Mime:         "application/octet-stream",
		LastModified: 1_700_000_000_000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		out *transfer.Outcome
		err error
	}
	sendCh := make(chan result, 1)
	recvCh := make(chan result, 1)

	go func() {
		out, err := transfer.Run(ctx, relay.off, transfer.Spec{
			Opaque: &rendezvous.OpaqueOptions{
				Role:              rendezvous.RoleOfferer,
				Handle:            handle,
				LocalIdentity:     idAlice,
				PeerDeviceID:      idBob.DeviceID,
				PeerPublicKey:     idBob.PublicKey,
				KPair:             kPair,
				PairCredentialRef: "cred-alice",
			},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		sendCh <- result{out, err}
	}()

	go func() {
		out, err := listener.HandleIncomingSession(ctx, relay.join, idAlice.DeviceID, handle)
		recvCh <- result{out, err}
	}()

	send := <-sendCh
	recv := <-recvCh

	if recv.err == nil {
		t.Fatal("expected receiver error due to declined consent, got nil")
	}
	if send.err == nil {
		t.Fatal("expected sender error due to declined consent, got nil")
	}

	if listener.VerifiedDeliveries() != 0 {
		t.Fatalf("verified deliveries = %d, want 0", listener.VerifiedDeliveries())
	}

	// Verify no files or journals were written to destDir
	entries, _ := os.ReadDir(destDir)
	if len(entries) != 0 {
		t.Fatalf("expected empty destDir, found: %+v", entries)
	}
}

func TestReceiverRevokedPeerRejected(t *testing.T) {
	tmpDir := t.TempDir()
	idAlice, idBob, _, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Revoke Alice in Bob's store
	recAlice, err := storeBob.GetDevice(context.Background(), idAlice.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	recAlice.Revoked = true
	now := time.Now().UTC()
	recAlice.RevokedAt = &now
	if err := storeBob.AddOrUpdateDevice(context.Background(), recAlice); err != nil {
		t.Fatal(err)
	}

	relay := newLoopbackRelay()
	listener, err := NewListener(Config{
		DestDir:    tmpDir,
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, recvErr := listener.HandleIncomingSession(ctx, relay.join, idAlice.DeviceID, handle)
	if recvErr == nil {
		t.Fatal("expected error for revoked peer, got nil")
	}
	if !errors.Is(recvErr, wire.ErrTrustedPeerRevoked) {
		t.Fatalf("expected ErrTrustedPeerRevoked, got %v", recvErr)
	}
}

func TestReceiverOnceModeSingleDelivery(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "once_dest")

	idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	relay := newLoopbackRelay()

	listener, err := NewListener(Config{
		DestDir:    destDir,
		AutoAccept: true,
		Once:       true, // --once mode!
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	payload := []byte("once mode verified delivery")
	meta := wire.FileMeta{
		Name:         "once.txt",
		Size:         int64(len(payload)),
		Mime:         "text/plain",
		LastModified: 1_700_000_000_000,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenerDone := make(chan error, 1)
	go func() {
		// Start in Once mode blocks until 1 verified delivery!
		err := listener.Start(ctx)
		listenerDone <- err
	}()

	// Simulate incoming transfer session on relay
	go func() {
		// Offerer sends
		go func() {
			_, _ = transfer.Run(ctx, relay.off, transfer.Spec{
				Opaque: &rendezvous.OpaqueOptions{
					Role:              rendezvous.RoleOfferer,
					Handle:            handle,
					LocalIdentity:     idAlice,
					PeerDeviceID:      idBob.DeviceID,
					PeerPublicKey:     idBob.PublicKey,
					KPair:             kPair,
					PairCredentialRef: "cred-alice",
				},
				Source:     wire.BytesSource(payload, meta, 64*1024),
				ICEServers: []webrtc.ICEServer{},
			})
		}()

		// Listener handles incoming session
		_, _ = listener.HandleIncomingSession(ctx, relay.join, idAlice.DeviceID, handle)
	}()

	select {
	case err := <-listenerDone:
		if err != nil {
			t.Fatalf("listener.Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener.Start did not terminate after single verified delivery in Once mode")
	}

	if listener.VerifiedDeliveries() != 1 {
		t.Fatalf("verified deliveries = %d, want 1", listener.VerifiedDeliveries())
	}
}

func TestReceiverOnceModeDeclinedDoesNotExit(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "once_dest2")

	idAlice, idBob, kPair, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)
	handle1 := "1111111111111111111111111111111111111111111111111111111111111111"
	handle2 := "2222222222222222222222222222222222222222222222222222222222222222"

	acceptSecond := false
	listener, err := NewListener(Config{
		DestDir: destDir,
		Once:    true, // --once mode
		ConsentHandler: func(_ context.Context, _ ConsentRequest) (ConsentDecision, error) {
			if !acceptSecond {
				return ConsentDecision{Accepted: false, Reason: "declined first"}, nil
			}
			return ConsentDecision{Accepted: true}, nil
		},
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listenerDone := make(chan error, 1)
	go func() {
		err := listener.Start(ctx)
		listenerDone <- err
	}()

	relay1 := newLoopbackRelay()
	payload1 := []byte("first transfer")
	meta1 := wire.FileMeta{Name: "file1.txt", Size: int64(len(payload1))}

	// First transfer attempt (declined)
	go func() {
		_, _ = transfer.Run(ctx, relay1.off, transfer.Spec{
			Opaque: &rendezvous.OpaqueOptions{
				Role: rendezvous.RoleOfferer, Handle: handle1, LocalIdentity: idAlice,
				PeerDeviceID: idBob.DeviceID, PeerPublicKey: idBob.PublicKey, KPair: kPair,
			},
			Source: wire.BytesSource(payload1, meta1, 64*1024), ICEServers: []webrtc.ICEServer{},
		})
	}()
	_, _ = listener.HandleIncomingSession(ctx, relay1.join, idAlice.DeviceID, handle1)

	// Ensure listener is STILL running after decline
	select {
	case <-listenerDone:
		t.Fatal("listener exited early after declined transfer; --once means one verified delivery!")
	case <-time.After(200 * time.Millisecond):
		// Expected: still listening!
	}

	if listener.VerifiedDeliveries() != 0 {
		t.Fatalf("expected 0 verified deliveries after decline, got %d", listener.VerifiedDeliveries())
	}

	// Now send second transfer and accept it
	acceptSecond = true
	relay2 := newLoopbackRelay()
	payload2 := []byte("second transfer verified")
	meta2 := wire.FileMeta{Name: "file2.txt", Size: int64(len(payload2))}

	go func() {
		_, _ = transfer.Run(ctx, relay2.off, transfer.Spec{
			Opaque: &rendezvous.OpaqueOptions{
				Role: rendezvous.RoleOfferer, Handle: handle2, LocalIdentity: idAlice,
				PeerDeviceID: idBob.DeviceID, PeerPublicKey: idBob.PublicKey, KPair: kPair,
			},
			Source: wire.BytesSource(payload2, meta2, 64*1024), ICEServers: []webrtc.ICEServer{},
		})
	}()
	_, _ = listener.HandleIncomingSession(ctx, relay2.join, idAlice.DeviceID, handle2)

	select {
	case err := <-listenerDone:
		if err != nil {
			t.Fatalf("listener.Start error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not exit after accepted verified delivery in once mode")
	}

	if listener.VerifiedDeliveries() != 1 {
		t.Fatalf("expected 1 verified delivery, got %d", listener.VerifiedDeliveries())
	}
}

func TestEvaluateConsentUnit(t *testing.T) {
	tmpDir := t.TempDir()
	idAlice, idBob, _, storeBob, _, tombstonesBob := setupPairedPeers(t, tmpDir)

	manifest := wire.Manifest{
		TransferID: "t-123",
		Files: []wire.FileEntry{
			{Idx: 0, Name: "doc.pdf", Size: 500, Mime: "application/pdf"},
		},
		TotalSize: 500,
	}

	// 1. Global auto-accept
	dec, err := EvaluateConsent(context.Background(), storeBob, tombstonesBob, true, "/default", idAlice.DeviceID, manifest, nil)
	if err != nil || !dec.Accepted || dec.DestDir != "/default" {
		t.Fatalf("expected global auto accept, got dec=%+v err=%v", dec, err)
	}

	// 2. Peer auto-accept with size limit exceeded
	err = storeBob.UpdatePolicy(context.Background(), idAlice.DeviceID, wire.TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: "/dest",
		MaxFileSizeBytes:  100, // file is 500, so exceeded
	})
	if err != nil {
		t.Fatal(err)
	}
	handlerCalled := false
	dec, err = EvaluateConsent(context.Background(), storeBob, tombstonesBob, false, "/default", idAlice.DeviceID, manifest, func(_ context.Context, _ ConsentRequest) (ConsentDecision, error) {
		handlerCalled = true
		return ConsentDecision{Accepted: false, Reason: "prompted"}, nil
	})
	if err != nil || !handlerCalled || dec.Accepted {
		t.Fatalf("expected fallback to handler due to size limit, got dec=%+v err=%v", dec, err)
	}

	// 3. Peer auto-accept with allowed mime types
	err = storeBob.UpdatePolicy(context.Background(), idAlice.DeviceID, wire.TrustPolicy{
		AutoAccept:        true,
		AutoAcceptDestDir: "/dest",
		MaxFileSizeBytes:  1000,
		AllowedMimeTypes:  []string{"image/png"}, // file is application/pdf, so mime disallowed
	})
	if err != nil {
		t.Fatal(err)
	}
	handlerCalled = false
	dec, err = EvaluateConsent(context.Background(), storeBob, tombstonesBob, false, "/default", idAlice.DeviceID, manifest, func(_ context.Context, _ ConsentRequest) (ConsentDecision, error) {
		handlerCalled = true
		return ConsentDecision{Accepted: false, Reason: "mime blocked"}, nil
	})
	if err != nil || !handlerCalled || dec.Accepted {
		t.Fatalf("expected fallback to handler due to mime, got dec=%+v err=%v", dec, err)
	}

	// 4. Tombstone revocation
	now := time.Now().UTC()
	tombstone, err := wire.SignRevocation(idBob, idAlice.DeviceID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tombstonesBob.StoreTombstone(context.Background(), tombstone); err != nil {
		t.Fatal(err)
	}
	dec, err = EvaluateConsent(context.Background(), storeBob, tombstonesBob, true, "/default", idAlice.DeviceID, manifest, nil)
	if !errors.Is(err, wire.ErrTrustedPeerRevoked) {
		t.Fatalf("expected ErrTrustedPeerRevoked from tombstone, got err=%v", err)
	}
}

func TestListenerPendingConsentAsync(t *testing.T) {
	tmpDir := t.TempDir()
	_, idBob, _, storeBob, secretsBob, tombstonesBob := setupPairedPeers(t, tmpDir)

	listener, err := NewListener(Config{
		DestDir:    tmpDir,
		Identity:   idBob,
		TrustStore: storeBob,
		Secrets:    secretsBob,
		Tombstones: tombstonesBob,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	// Initially empty pending consent
	if len(listener.PendingConsent()) != 0 {
		t.Fatalf("expected 0 pending consent requests, got %d", len(listener.PendingConsent()))
	}

	// Unknown transfer ID respond returns error
	err = listener.RespondConsent("nonexistent", ConsentDecision{Accepted: true})
	if err == nil {
		t.Fatal("expected error responding to nonexistent consent request")
	}
}

