package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/sendbeam/wire"
)

// mockPairingTransport simulates in-memory duplex messaging between two peers.
type mockPairingTransport struct {
	in  chan []byte
	out chan []byte
}

func newMockPairingPipe() (PairingTransport, PairingTransport) {
	a2b := make(chan []byte, 10)
	b2a := make(chan []byte, 10)
	tA := &mockPairingTransport{in: b2a, out: a2b}
	tB := &mockPairingTransport{in: a2b, out: b2a}
	return tA, tB
}

func (m *mockPairingTransport) SendMessage(ctx context.Context, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.out <- append([]byte(nil), data...):
		return nil
	}
}

func (m *mockPairingTransport) ReceiveMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-m.in:
		return data, nil
	}
}

func (m *mockPairingTransport) Close() error {
	return nil
}

func TestThreeDevice_MeshRevocationSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Setup Identities for Device A (Laptop), Device B (Phone), and Device C (Workstation)
	seedA := sha256.Sum256([]byte("seed-device-a-laptop"))
	privA := ed25519.NewKeyFromSeed(seedA[:])
	idA, err := wire.NewDeviceIdentity(privA.Public().(ed25519.PublicKey), privA)
	if err != nil {
		t.Fatal(err)
	}

	seedB := sha256.Sum256([]byte("seed-device-b-phone"))
	privB := ed25519.NewKeyFromSeed(seedB[:])
	idB, err := wire.NewDeviceIdentity(privB.Public().(ed25519.PublicKey), privB)
	if err != nil {
		t.Fatal(err)
	}

	seedC := sha256.Sum256([]byte("seed-device-c-workstation"))
	privC := ed25519.NewKeyFromSeed(seedC[:])
	idC, err := wire.NewDeviceIdentity(privC.Public().(ed25519.PublicKey), privC)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Setup Shared Pair Secrets
	kPairAB := sha256.Sum256([]byte("secret-pair-a-b"))
	kPairAC := sha256.Sum256([]byte("secret-pair-a-c"))
	kPairBC := sha256.Sum256([]byte("secret-pair-b-c"))

	refAB := "cred-ab-" + hex.EncodeToString(kPairAB[:8])
	refAC := "cred-ac-" + hex.EncodeToString(kPairAC[:8])
	refBC := "cred-bc-" + hex.EncodeToString(kPairBC[:8])

	// 3. Setup Stores and Coordinators
	storeA := NewMemoryTrustStore()
	storeB := NewMemoryTrustStore()
	storeC := NewMemoryTrustStore()

	resA := NewMemorySecretResolver()
	resB := NewMemorySecretResolver()
	resC := NewMemorySecretResolver()

	resA.SetSecret(idB.DeviceID, kPairAB[:])
	resA.SetSecret(idC.DeviceID, kPairAC[:])

	resB.SetSecret(idA.DeviceID, kPairAB[:])
	resB.SetSecret(idC.DeviceID, kPairBC[:])

	resC.SetSecret(idA.DeviceID, kPairAC[:])
	resC.SetSecret(idB.DeviceID, kPairBC[:])

	coordA := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idA), storeA, resA)
	coordB := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idB), storeB, resB)
	coordC := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idC), storeC, resC)

	// Populate Pairings:
	// A is paired with B and C
	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         idB.PublicKeyHex(),
		LocalLabel:        "Phone",
		PairCredentialRef: refAB,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idC.DeviceID,
		PublicKey:         idC.PublicKeyHex(),
		LocalLabel:        "Workstation",
		PairCredentialRef: refAC,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	// B is paired with A and C
	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idA.DeviceID,
		PublicKey:         idA.PublicKeyHex(),
		LocalLabel:        "Laptop",
		PairCredentialRef: refAB,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idC.DeviceID,
		PublicKey:         idC.PublicKeyHex(),
		LocalLabel:        "Workstation",
		PairCredentialRef: refBC,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	// C is paired with A and B
	_ = storeC.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idA.DeviceID,
		PublicKey:         idA.PublicKeyHex(),
		LocalLabel:        "Laptop",
		PairCredentialRef: refAC,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeC.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         idB.PublicKeyHex(),
		LocalLabel:        "Phone",
		PairCredentialRef: refBC,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	// Verify all are trusted initially
	if !storeA.IsTrusted(ctx, idB.DeviceID) || !storeC.IsTrusted(ctx, idB.DeviceID) {
		t.Fatal("expected Device B to be trusted initially by A and C")
	}

	// 4. Device A revokes Device B (signing a mesh RevocationRecord)
	if err := coordA.RevokeDevice(ctx, idB.DeviceID); err != nil {
		t.Fatalf("Device A RevokeDevice failed: %v", err)
	}

	if storeA.IsTrusted(ctx, idB.DeviceID) {
		t.Fatal("Device A should no longer trust Device B")
	}

	// Before syncing with A, C still trusts B
	if !storeC.IsTrusted(ctx, idB.DeviceID) {
		t.Fatal("Device C should still trust B before receiving revocation sync")
	}

	// 5. Device A and Device C establish a sendbeam/2 session
	pipeAtoC, pipeCfromA := newMockPairingPipe()

	errChA := make(chan error, 1)
	errChC := make(chan error, 1)

	go func() {
		_, err := coordA.InitiateTrustedSession(ctx, pipeAtoC, TrustedSessionConfig{
			PeerDeviceID: idC.DeviceID,
			Capabilities: []string{wire.CapTransferV1},
		})
		errChA <- err
	}()

	go func() {
		_, err := coordC.AcceptTrustedSession(ctx, pipeCfromA, []string{wire.CapTransferV1})
		errChC <- err
	}()

	if err := <-errChA; err != nil {
		t.Fatalf("InitiateTrustedSession A->C failed: %v", err)
	}
	if err := <-errChC; err != nil {
		t.Fatalf("AcceptTrustedSession C<-A failed: %v", err)
	}

	// 6. Verify Device C learned that Device B was revoked by Device A
	if storeC.IsTrusted(ctx, idB.DeviceID) {
		t.Fatal("Device C should NOT trust Device B after syncing with Device A")
	}

	devBOnC, err := storeC.GetDevice(ctx, idB.DeviceID)
	if err != nil {
		t.Fatalf("GetDevice B on C failed: %v", err)
	}
	if !devBOnC.Revoked {
		t.Fatal("expected devBOnC.Revoked to be true")
	}
	if devBOnC.RevokedBy != idA.DeviceID {
		t.Fatalf("expected RevokedBy %s, got %s", idA.DeviceID, devBOnC.RevokedBy)
	}
	if devBOnC.RevocationSeq != 1 {
		t.Fatalf("expected RevocationSeq 1, got %d", devBOnC.RevocationSeq)
	}

	// 7. Device B attempts to initiate a trusted session with Device C -> C rejects B fail-closed!
	pipeBtoC, pipeCfromB := newMockPairingPipe()

	go func() {
		_, _ = coordB.InitiateTrustedSession(ctx, pipeBtoC, TrustedSessionConfig{
			PeerDeviceID: idC.DeviceID,
			Capabilities: []string{wire.CapTransferV1},
		})
	}()

	_, err = coordC.AcceptTrustedSession(ctx, pipeCfromB, []string{wire.CapTransferV1})
	if err == nil {
		t.Fatal("expected Device C to reject revoked Device B, but AcceptTrustedSession succeeded")
	}
	if !errors.Is(err, wire.ErrTrustedPeerRevoked) {
		t.Fatalf("expected ErrTrustedPeerRevoked, got: %v", err)
	}
}
