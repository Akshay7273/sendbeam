package rendezvous

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/sendbeam/wire"
)

type mockSink struct {
	mu   sync.Mutex
	msgs []Message
}

func (m *mockSink) Send(msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *mockSink) GetMsgs() []Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Message, len(m.msgs))
	copy(cp, m.msgs)
	return cp
}

func TestOpaqueSessionMouthToEar(t *testing.T) {
	// Generate identities for Alice (Offerer) and Bob (Joiner)
	idAlice, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity Alice: %v", err)
	}
	idBob, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity Bob: %v", err)
	}

	kPair := sha256.Sum256([]byte("shared-kpair-12345"))
	validHandle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	sinkAlice := &mockSink{}
	sinkBob := &mockSink{}

	optsAlice := OpaqueOptions{
		Role:              RoleOfferer,
		Handle:            validHandle,
		LocalIdentity:     idAlice,
		PeerDeviceID:      idBob.DeviceID,
		PeerPublicKey:     idBob.PublicKey,
		KPair:             kPair[:],
		PairCredentialRef: "cred-1",
		Transport:         sinkAlice,
	}

	optsBob := OpaqueOptions{
		Role:              RoleJoiner,
		Handle:            validHandle,
		LocalIdentity:     idBob,
		PeerDeviceID:      idAlice.DeviceID,
		PeerPublicKey:     idAlice.PublicKey,
		KPair:             kPair[:],
		PairCredentialRef: "cred-1",
		Transport:         sinkBob,
	}

	sessionAlice := NewOpaqueSession(optsAlice)
	sessionBob := NewOpaqueSession(optsBob)

	// 1. Alice starts
	if err := sessionAlice.Start(); err != nil {
		t.Fatalf("sessionAlice.Start: %v", err)
	}
	if sessionAlice.Phase() != OpaquePhaseRendezvousSent {
		t.Fatalf("expected OpaquePhaseRendezvousSent, got %v", sessionAlice.Phase())
	}
	msgsAlice := sinkAlice.GetMsgs()
	if len(msgsAlice) != 1 || msgsAlice[0].Type != typeRendezvous || msgsAlice[0].Handle != validHandle {
		t.Fatalf("unexpected rendezvous msg: %+v", msgsAlice)
	}

	// Server sends created to Alice
	if err := sessionAlice.Handle(Message{Type: typeCreated, Handle: validHandle}); err != nil {
		t.Fatalf("sessionAlice.Handle(created): %v", err)
	}
	if sessionAlice.Phase() != OpaquePhaseWaitingPeer {
		t.Fatalf("expected OpaquePhaseWaitingPeer, got %v", sessionAlice.Phase())
	}

	// 2. Bob starts
	if err := sessionBob.Start(); err != nil {
		t.Fatalf("sessionBob.Start: %v", err)
	}
	if sessionBob.Phase() != OpaquePhaseRendezvousSent {
		t.Fatalf("expected OpaquePhaseRendezvousSent, got %v", sessionBob.Phase())
	}

	// Server signals peer-joined to Alice
	if err := sessionAlice.Handle(Message{Type: typePeerJoined, Role: "offerer"}); err != nil {
		t.Fatalf("sessionAlice.Handle(peer-joined): %v", err)
	}
	if sessionAlice.Phase() != OpaquePhaseAuthenticating {
		t.Fatalf("expected OpaquePhaseAuthenticating, got %v", sessionAlice.Phase())
	}

	// Alice emitted trusted_auth_init
	msgsAlice = sinkAlice.GetMsgs()
	if len(msgsAlice) != 2 || msgsAlice[1].Type != typeTrustedAuthInit {
		t.Fatalf("expected trusted_auth_init, got %+v", msgsAlice)
	}
	initMsg := msgsAlice[1]

	// Bob receives trusted_auth_init
	if err := sessionBob.Handle(initMsg); err != nil {
		t.Fatalf("sessionBob.Handle(init): %v", err)
	}

	// Bob emitted trusted_auth_response and trusted_auth_confirm
	msgsBob := sinkBob.GetMsgs()
	if len(msgsBob) != 3 {
		t.Fatalf("expected 3 msgs from Bob, got %d", len(msgsBob))
	}
	if msgsBob[1].Type != typeTrustedAuthResponse || msgsBob[2].Type != typeTrustedAuthConfirm {
		t.Fatalf("unexpected msgs from Bob: %+v", msgsBob)
	}
	respMsg := msgsBob[1]
	bobConfirm := msgsBob[2]

	// Alice receives trusted_auth_response
	if err := sessionAlice.Handle(respMsg); err != nil {
		t.Fatalf("sessionAlice.Handle(resp): %v", err)
	}

	// Alice emitted trusted_auth_confirm
	msgsAlice = sinkAlice.GetMsgs()
	if len(msgsAlice) != 3 || msgsAlice[2].Type != typeTrustedAuthConfirm {
		t.Fatalf("expected trusted_auth_confirm from Alice, got %+v", msgsAlice)
	}
	aliceConfirm := msgsAlice[2]

	// Mutual confirmation
	if err := sessionAlice.Handle(bobConfirm); err != nil {
		t.Fatalf("sessionAlice.Handle(bobConfirm): %v", err)
	}
	if err := sessionBob.Handle(aliceConfirm); err != nil {
		t.Fatalf("sessionBob.Handle(aliceConfirm): %v", err)
	}

	// Both should be established!
	if sessionAlice.Phase() != OpaquePhaseEstablished {
		t.Fatalf("expected Alice established, got %v", sessionAlice.Phase())
	}
	if sessionBob.Phase() != OpaquePhaseEstablished {
		t.Fatalf("expected Bob established, got %v", sessionBob.Phase())
	}

	resAlice, err := sessionAlice.Wait()
	if err != nil {
		t.Fatalf("sessionAlice.Wait: %v", err)
	}
	resBob, err := sessionBob.Wait()
	if err != nil {
		t.Fatalf("sessionBob.Wait: %v", err)
	}

	// Verify session keys match
	if !bytes.Equal(resAlice.Master, resBob.Master) {
		t.Fatalf("session master mismatch between Alice and Bob")
	}
	if !bytes.Equal(resAlice.SendKey, resBob.RecvKey) {
		t.Fatalf("directional key mismatch: Alice SendKey != Bob RecvKey")
	}
	if !bytes.Equal(resAlice.RecvKey, resBob.SendKey) {
		t.Fatalf("directional key mismatch: Alice RecvKey != Bob SendKey")
	}
	if resAlice.Role != RoleOfferer || resBob.Role != RoleJoiner {
		t.Fatalf("role mismatch")
	}
	if resAlice.Handle != validHandle || resBob.Handle != validHandle {
		t.Fatalf("handle mismatch")
	}
	if resAlice.PeerDeviceID != idBob.DeviceID || resBob.PeerDeviceID != idAlice.DeviceID {
		t.Fatalf("peer device ID mismatch")
	}
}

func TestOpaqueSessionInvalidHandle(t *testing.T) {
	id, _ := wire.GenerateDeviceIdentity()
	pub, _, _ := ed25519.GenerateKey(nil)
	kPair := make([]byte, 32)

	session := NewOpaqueSession(OpaqueOptions{
		Role:          RoleOfferer,
		Handle:        "short-handle",
		LocalIdentity: id,
		PeerDeviceID:  "dev-peer",
		PeerPublicKey: pub,
		KPair:         kPair,
		Transport:     &mockSink{},
	})

	err := session.Start()
	if err == nil {
		t.Fatalf("expected error on invalid handle")
	}
	if session.Phase() != OpaquePhaseFailed {
		t.Fatalf("expected failed phase, got %v", session.Phase())
	}
}

func TestOpaqueSessionPeerLeft(t *testing.T) {
	id, _ := wire.GenerateDeviceIdentity()
	pub, _, _ := ed25519.GenerateKey(nil)
	kPair := make([]byte, 32)
	validHandle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	session := NewOpaqueSession(OpaqueOptions{
		Role:          RoleOfferer,
		Handle:        validHandle,
		LocalIdentity: id,
		PeerDeviceID:  "dev-peer",
		PeerPublicKey: pub,
		KPair:         kPair,
		Transport:     &mockSink{},
	})

	_ = session.Start()
	err := session.Handle(Message{Type: typePeerLeft})
	if err == nil {
		t.Fatalf("expected error on peer_left")
	}
	if session.Phase() != OpaquePhaseFailed {
		t.Fatalf("expected failed phase, got %v", session.Phase())
	}
}
