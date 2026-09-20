package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// resolvedTarget is one trusted device with its send credentials resolved:
// the trust record, the pair secret, and the peer's public key. The peer
// identity bound into the transfer comes from these values, never from a
// label or a job file.
type resolvedTarget struct {
	query      string
	record     *wire.TrustRecord
	kPair      []byte
	peerPubKey ed25519.PublicKey
}

// targetSendConfig carries the transport and privacy options for building a
// targeted transfer. Shared by `send --to` and the outbox dispatcher so both
// production paths bind peers identically.
type targetSendConfig struct {
	server         string
	insecure       bool
	relayOnly      bool
	ice            []webrtc.ICEServer
	privateMode    bool
	requirePadding bool
	jitter         time.Duration
	dialWriter     io.Writer
	// contentKind marks a targeted send as an encrypted text/link handoff
	// (V20-PR06); empty for ordinary file sends.
	contentKind string
}

// resolveSendTargets resolves each query to a trusted device and loads the
// pair secret and peer public key it needs for an authenticated send.
// Revoked devices, missing secrets, and bad public keys fail closed.
func resolveSendTargets(ctx context.Context, env *CLIEnvironment, queries []string) ([]resolvedTarget, error) {
	var resolved []resolvedTarget
	for _, q := range queries {
		dev, err := ResolveDevice(ctx, env.TrustStore, q)
		if err != nil {
			return nil, err
		}
		if dev.Revoked || (env.Tombstones != nil && env.Tombstones.HasTombstone(ctx, dev.DeviceID)) {
			return nil, fmt.Errorf("trust for device %q is revoked", dev.LocalLabel)
		}
		kPair, err := env.Secrets.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			return nil, fmt.Errorf("failed to resolve pair secret for device %q: %v", dev.LocalLabel, err)
		}
		peerPubKey, err := wire.ParsePublicKeyHex(dev.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key for device %q: %v", dev.LocalLabel, err)
		}
		resolved = append(resolved, resolvedTarget{
			query:      q,
			record:     dev,
			kPair:      kPair,
			peerPubKey: peerPubKey,
		})
	}
	return resolved, nil
}

// buildBroadcastTargets constructs one transfer target per resolved device,
// binding the authenticated peer identity (device ID, public key, pair
// secret) into the opaque rendezvous options and the transfer spec.
func buildBroadcastTargets(env *CLIEnvironment, localID *wire.DeviceIdentity, resolved []resolvedTarget, sources []wire.FileSource, cfg targetSendConfig) []transfer.BroadcastTarget {
	replayCache := wire.NewNonceReplayCache(5 * time.Minute)
	targets := make([]transfer.BroadcastTarget, len(resolved))
	for i, r := range resolved {
		rec := r.record
		handle := wire.DeriveRendezvousHandleForTime(r.kPair, time.Now().UTC(), wire.DefaultRendezvousEpochWindow)
		opaqueOpts := &rendezvous.OpaqueOptions{
			Role:              rendezvous.RoleOfferer,
			Handle:            handle,
			LocalIdentity:     localID,
			PeerDeviceID:      rec.DeviceID,
			PeerPublicKey:     r.peerPubKey,
			KPair:             r.kPair,
			PairCredentialRef: rec.PairCredentialRef,
			// V20-PR06: advertise handoff support so the negotiated
			// intersection can grant it; without this the driver's
			// fail-closed downgrade check would refuse every targeted
			// handoff even to a capable peer.
			LocalCaps:   []string{"sendbeam/3", "rendezvous", "resume", wire.HandoffCapability},
			ReplayCache: replayCache,
			Tombstones:  env.Tombstones,
			TrustStore:  env.TrustStore,
		}
		requirePad := cfg.requirePadding || rec.Policy.RequirePadding
		spec := transfer.Spec{
			Opaque:         opaqueOpts,
			PeerDeviceID:   rec.DeviceID,
			PeerLabel:      rec.LocalLabel,
			Sources:        sources,
			ContentKind:    cfg.contentKind,
			ICEServers:     cfg.ice,
			ForceRelay:     cfg.relayOnly,
			Private:        cfg.privateMode || requirePad,
			RequirePadding: requirePad,
			RelayJitter:    cfg.jitter,
		}
		targets[i] = transfer.BroadcastTarget{
			ID:    rec.DeviceID,
			Label: rec.LocalLabel,
			Dial: func(dialCtx context.Context) (transfer.Signal, error) {
				return dial(dialCtx, cfg.server, cfg.insecure, cfg.dialWriter)
			},
			Spec: spec,
		}
	}
	return targets
}
