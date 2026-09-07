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

	clusterID := "sb-cluster-owner-123"

	// Populate Pairings:
	// A is paired with B and C
	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         idB.PublicKeyHex(),
		LocalLabel:        "Phone",
		PairCredentialRef: refAB,
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeA.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idC.DeviceID,
		PublicKey:         idC.PublicKeyHex(),
		LocalLabel:        "Workstation",
		PairCredentialRef: refAC,
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
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
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeB.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idC.DeviceID,
		PublicKey:         idC.PublicKeyHex(),
		LocalLabel:        "Workstation",
		PairCredentialRef: refBC,
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
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
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
		Capabilities:      []string{wire.CapTransferV1},
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = storeC.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idB.DeviceID,
		PublicKey:         idB.PublicKeyHex(),
		LocalLabel:        "Phone",
		PairCredentialRef: refBC,
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
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

func newTestIdentity(t *testing.T, seedStr string) *wire.DeviceIdentity {
	t.Helper()
	seed := sha256.Sum256([]byte(seedStr))
	priv := ed25519.NewKeyFromSeed(seed[:])
	id, err := wire.NewDeviceIdentity(priv.Public().(ed25519.PublicKey), priv)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRevocation_UnauthorizedContactRejection(t *testing.T) {
	ctx := context.Background()
	idOwner := newTestIdentity(t, "seed-owner")
	idContact := newTestIdentity(t, "seed-contact")
	idTarget := newTestIdentity(t, "seed-target")

	store := NewMemoryTrustStore()
	tombstones := NewMemoryTombstoneStore()
	credStore := NewMemoryCredentialStore()

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idContact.DeviceID,
		PublicKey:         idContact.PublicKeyHex(),
		LocalLabel:        "Contact Alice",
		PairCredentialRef: "cred-contact",
		Relationship:      wire.RelationshipContact,
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idTarget.DeviceID,
		PublicKey:         idTarget.PublicKeyHex(),
		LocalLabel:        "Contact Bob",
		PairCredentialRef: "cred-target",
		Relationship:      wire.RelationshipContact,
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	coord := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idOwner), store, NewMemorySecretResolver())
	coord.SetTombstoneStore(tombstones)
	coord.SetCredentialStore(credStore)

	// Contact Alice attempts to revoke Contact Bob
	rec, err := wire.SignRevocation(idContact, idTarget.DeviceID, 1, time.Now().UTC())
	if err != nil {
		t.Fatalf("SignRevocation failed: %v", err)
	}

	err = coord.IngestRevocationRecord(ctx, rec)
	if !errors.Is(err, wire.ErrRevocationUnauthorized) {
		t.Fatalf("expected ErrRevocationUnauthorized, got: %v", err)
	}

	// Target Bob must remain trusted
	if !store.IsTrusted(ctx, idTarget.DeviceID) {
		t.Fatal("target Bob should remain trusted after unauthorized revocation attempt")
	}
}

func TestRevocation_SelfTombstoneUnknownDevice(t *testing.T) {
	ctx := context.Background()
	idLocal := newTestIdentity(t, "seed-local")
	idUnknown := newTestIdentity(t, "seed-unknown")

	store := NewMemoryTrustStore()
	tombstones := NewMemoryTombstoneStore()
	coord := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idLocal), store, NewMemorySecretResolver())
	coord.SetTombstoneStore(tombstones)

	// Unknown device signs a self-tombstone
	rec, err := wire.SignSelfTombstone(idUnknown, 1, time.Now().UTC())
	if err != nil {
		t.Fatalf("SignSelfTombstone failed: %v", err)
	}

	// Ingest self-tombstone
	err = coord.IngestRevocationRecord(ctx, rec)
	if err != nil {
		t.Fatalf("expected nil for valid self-tombstone of unknown device, got: %v", err)
	}

	// Tombstone store must now contain the record
	if !tombstones.HasTombstone(ctx, idUnknown.DeviceID) {
		t.Fatal("expected TombstoneStore to contain tombstone for unknown device")
	}
}

func TestRevocation_ActiveSessionAbort(t *testing.T) {
	ctx := context.Background()
	idLocal := newTestIdentity(t, "seed-local-abort")
	idPeer := newTestIdentity(t, "seed-peer-abort")

	store := NewMemoryTrustStore()
	tombstones := NewMemoryTombstoneStore()
	credStore := NewMemoryCredentialStore()
	resolver := NewMemorySecretResolver()

	var dummyKey [32]byte
	resolver.SetSecret(idPeer.DeviceID, dummyKey[:])
	_ = credStore.SetPairSecret(ctx, idPeer.DeviceID, "cred-peer", dummyKey[:])

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idPeer.DeviceID,
		PublicKey:         idPeer.PublicKeyHex(),
		LocalLabel:        "Peer Bob",
		PairCredentialRef: "cred-peer",
		Relationship:      wire.RelationshipContact,
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})

	coord := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idLocal), store, resolver)
	coord.SetTombstoneStore(tombstones)
	coord.SetCredentialStore(credStore)

	// Register active in-flight session
	sessionCanceled := false
	cancelFn := func() {
		sessionCanceled = true
	}
	unregister := coord.RegisterActiveSession(idPeer.DeviceID, cancelFn)
	defer unregister()

	// Local device revokes Peer Bob
	err := coord.RevokeDevice(ctx, idPeer.DeviceID)
	if err != nil {
		t.Fatalf("RevokeDevice failed: %v", err)
	}

	// Assert active session was immediately canceled
	if !sessionCanceled {
		t.Fatal("expected active session to be canceled on revocation")
	}

	// Credential secret must be deleted
	_, err = credStore.ResolvePairSecret(ctx, idPeer.DeviceID, "cred-peer")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound from deleted secret, got: %v", err)
	}

	// Peer must not be trusted
	if store.IsTrusted(ctx, idPeer.DeviceID) {
		t.Fatal("peer should not be trusted post-revocation")
	}
}

func TestRevocation_MonotonicSequenceRollback(t *testing.T) {
	ctx := context.Background()
	idClusterOwner := newTestIdentity(t, "seed-cluster-owner-seq")
	idClusterMember := newTestIdentity(t, "seed-cluster-member-seq")
	idTarget := newTestIdentity(t, "seed-target-seq")

	clusterID := "sb-cluster-seq-test"
	store := NewMemoryTrustStore()

	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idClusterOwner.DeviceID,
		PublicKey:         idClusterOwner.PublicKeyHex(),
		LocalLabel:        "Admin",
		PairCredentialRef: "cred-admin",
		Relationship:      wire.RelationshipClusterOwner,
		ClusterID:         clusterID,
		FirstSeenAt:       time.Now().UTC(),
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = store.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          idTarget.DeviceID,
		PublicKey:         idTarget.PublicKeyHex(),
		LocalLabel:        "Target",
		PairCredentialRef: "cred-target",
		Relationship:      wire.RelationshipClusterMember,
		ClusterID:         clusterID,
		FirstSeenAt:       time.Now().UTC(),
		Revoked:           true,
		RevocationSeq:     2,
		Policy:            wire.DefaultTrustPolicy(),
	})

	coord := NewTrustedSessionCoordinator(NewMemoryIdentityManager(idClusterMember), store, NewMemorySecretResolver())
	coord.SetClusterID(clusterID)

	// Admin attempts to submit seq 2 (equal to current seq 2) -> SeqRollback
	recEq, err := wire.SignRevocation(idClusterOwner, idTarget.DeviceID, 2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := coord.IngestRevocationRecord(ctx, recEq); !errors.Is(err, wire.ErrRevocationSeqRollback) {
		t.Fatalf("expected ErrRevocationSeqRollback on equal seq, got: %v", err)
	}

	// Admin attempts to submit seq 1 (lower than current seq 2) -> SeqRollback
	recLow, err := wire.SignRevocation(idClusterOwner, idTarget.DeviceID, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := coord.IngestRevocationRecord(ctx, recLow); !errors.Is(err, wire.ErrRevocationSeqRollback) {
		t.Fatalf("expected ErrRevocationSeqRollback on lower seq, got: %v", err)
	}

	// Admin submits seq 3 -> succeeds
	recHigh, err := wire.SignRevocation(idClusterOwner, idTarget.DeviceID, 3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := coord.IngestRevocationRecord(ctx, recHigh); err != nil {
		t.Fatalf("expected seq 3 to succeed, got: %v", err)
	}

	updated, err := store.GetDevice(ctx, idTarget.DeviceID)
	if err != nil || updated.RevocationSeq != 3 {
		t.Fatalf("expected target seq 3, got: %v, seq %d", err, updated.RevocationSeq)
	}
}

func TestPairingCoordinator_RejectsTombstonedPeer(t *testing.T) {
	ctx := context.Background()
	idLocal := newTestIdentity(t, "seed-pair-local")
	idTombstoned := newTestIdentity(t, "seed-pair-tombstoned")

	store := NewMemoryTrustStore()
	tombstones := NewMemoryTombstoneStore()
	credStore := NewMemoryCredentialStore()

	// Store tombstone for idTombstoned
	tombstoneRec, err := wire.SignSelfTombstone(idTombstoned, 1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tombstones.StoreTombstone(ctx, tombstoneRec); err != nil {
		t.Fatal(err)
	}

	coord := NewPairingCoordinatorWithCredentials(NewMemoryIdentityManager(idLocal), store, credStore)
	coord.SetTombstoneStore(tombstones)

	pipe1, pipe2 := newMockPairingPipe()
	masterKey := []byte("01234567890123456789012345678901")

	errCh := make(chan error, 1)
	go func() {
		// Peer acts as initiator with idTombstoned
		initCoord := NewPairingCoordinator(NewMemoryIdentityManager(idTombstoned), NewMemoryTrustStore())
		_, err := initCoord.InitiatePairing(ctx, pipe1, PairingSessionConfig{
			DeviceName:   "Tombstoned Device",
			Capabilities: []string{wire.CapTransferV1},
			MasterKey:    masterKey,
		})
		errCh <- err
	}()

	_, err = coord.AcceptPairing(ctx, pipe2, PairingSessionConfig{
		DeviceName:   "Local Device",
		Capabilities: []string{wire.CapTransferV1},
		MasterKey:    masterKey,
	})
	if err == nil {
		t.Fatal("expected pairing coordinator to reject tombstoned peer")
	}
	if !errors.Is(err, wire.ErrTrustedPeerRevoked) {
		t.Fatalf("expected ErrTrustedPeerRevoked, got: %v", err)
	}
	<-errCh
}
