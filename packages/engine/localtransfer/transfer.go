// Package localtransfer performs native local-only transfers through the
// shared transfer engine for SendBeam v2.1 "Nearby & Offline" (ADR 0011).
//
// It connects an authenticated local rendezvous session (see localrendezvous)
// to transfer.Run: the same encrypted transfer machinery the online path
// uses — per-recipient identity binding, receiver consent, strict padding,
// backpressure, limits, and encrypted transfer framing — but with every
// non-local egress structurally removed:
//
//   - signaling runs over the local rendezvous session, never the public
//     rendezvous server;
//   - ICE uses an explicit empty server list, so only host candidates are
//     gathered (no STUN/TURN);
//   - the relay path is disabled (transfer.Spec.DisableRelay): a failed
//     direct path fails closed instead of falling back anywhere;
//   - dials go only to the pinned, policy-approved IPs from discovery's
//     validated route candidates, and every dial flows through an auditable
//     hook so a host can deny and monitor egress.
//
// Authentication is the existing reviewed paired-device ceremony
// (rendezvous.OpaqueOptions, ADR 0010 trusted sessions): the peer must prove
// knowledge of the pair secret bound to the trust-store public key for the
// selected device ID. First-time offline pairing is V21-PR05 and is not
// handled here.
package localtransfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pion/webrtc/v4"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/rtc"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// Options configures one local-only transfer.
type Options struct {
	// Identity is the local device identity used in the Opaque handshake.
	Identity *wire.DeviceIdentity
	// Store is the trust store: peer admission and peer public-key lookup.
	Store trust.Store
	// Resolver resolves the k_pair secret for the peer device.
	Resolver trust.SecretResolver
	// Table holds validated route candidates (see discovery).
	Table *discovery.CandidateTable
	// PeerDeviceID selects the candidate and the authenticated peer identity.
	PeerDeviceID string
	// PeerLabel is the human-readable peer label for consent prompts.
	PeerLabel string
	// Role is rendezvous.RoleOfferer (send) or rendezvous.RoleJoiner (receive).
	Role rendezvous.Role
	// Provenance is the advisory routine origin label (V22-PR06): nil for
	// ordinary one-off sends. It is stamped on the wire manifest (offerer)
	// so the receiver's consent surface can show where the transfer came
	// from. Informational only — never a trust signal.
	Provenance *wire.Provenance
	// Handle is the opaque session handle; empty mints a random one.
	Handle string

	// Source / Sources is the file or folder set to send (offerer only).
	Source  wire.FileSource
	Sources []wire.FileSource
	// DestDir receives files (joiner only).
	DestDir string
	// Consent evaluates the incoming transfer (joiner). Nil accepts into
	// DestDir per the engine default; pass an explicit handler to prompt.
	Consent transfer.ConsentHandler

	// RequirePadding enforces the traffic-padding policy; Private negotiates
	// padding. Both are passed straight to the shared engine.
	RequirePadding bool
	Private        bool

	// TransferID, when set, is advertised as the stable transfer id in the
	// manifest so an interrupted local send can be correlated with a
	// resumed session (V21-PR07). Empty mints a fresh id.
	TransferID string
	// Resume carries the cross-session resume context for an interrupted
	// local send that holds a resume credential (V21-PR07). It is set only
	// when the caller can authenticate a resume for this attempt; the
	// shared engine reuses durable progress only after the mutual
	// resume-auth preamble succeeds, under a fresh key epoch — a restart
	// never resets a nonce under the same key.
	Resume *transfer.ResumeContext
	// OnResume reports the cross-session resume decision for UX.
	OnResume func(transfer.ResumeResult)

	// OnSendManifest, when set, is wired into the engine's manifest hook:
	// it runs when the manifest frame goes out, before any bytes move.
	// The CLI passes the sender-store hook so a durable sender record is
	// created (or verified, on retry) for every local send — the same
	// resume contract as the online path (V21-PR07).
	OnSendManifest func(wire.Manifest) error

	// OnResumeCredential, when set, persists the transfer-scoped resume
	// credential into the sender record strictly before the manifest
	// frame is transmitted, enabling authenticated cross-session resume
	// with fresh keys via the existing resume contract (V21-PR07).
	OnResumeCredential func(wire.Manifest, []byte) error

	// Dial performs the TCP dial. Nil uses a default dialer. Every outbound
	// connection the local path makes flows through it, so a host can deny
	// and monitor egress (see localrendezvous.DialConfig).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// OnTransport reports the selected byte path ("direct" in local-only).
	OnTransport func(string)
	// OnProgress reports cumulative bytes acknowledged after verify-and-sink.
	OnProgress func(int64)
	// OnManifest fires on the receiver when the sender's manifest arrives.
	OnManifest func(wire.FileEntry)
	// OnConnect fires once the data channel opens, before bytes move.
	OnConnect func()
}

func (o Options) validate() error {
	if o.Identity == nil {
		return errors.New("localtransfer: missing local identity")
	}
	if o.Store == nil {
		return errors.New("localtransfer: missing trust store")
	}
	if o.Resolver == nil {
		return errors.New("localtransfer: missing secret resolver")
	}
	if o.Table == nil {
		return errors.New("localtransfer: missing candidate table")
	}
	if o.PeerDeviceID == "" {
		return errors.New("localtransfer: missing peer device ID")
	}
	if o.Role != rendezvous.RoleOfferer && o.Role != rendezvous.RoleJoiner {
		return errors.New("localtransfer: role must be offerer or joiner")
	}
	if o.Role == rendezvous.RoleOfferer && o.Source == nil && len(o.Sources) == 0 {
		return errors.New("localtransfer: offerer needs a source")
	}
	if o.Role == rendezvous.RoleJoiner && o.DestDir == "" {
		return errors.New("localtransfer: joiner needs a destination directory")
	}
	return nil
}

// Transfer performs one local-only transfer with a paired device: it takes
// the validated route candidate for PeerDeviceID, dials the pinned local
// endpoint, and runs the shared encrypted transfer engine over the
// authenticated local session.
//
// There is no online fallback at any step: no route candidate, a refused or
// unreachable endpoint, a failed handshake, or a failed direct path each
// return a clear error.
func Transfer(ctx context.Context, opts Options) (*transfer.Outcome, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	// The route comes only from validated candidates. No candidate means no
	// local route: fail clearly instead of reaching for any online path.
	ep, ok := opts.Table.TakeForDial(opts.PeerDeviceID)
	if !ok {
		return nil, fmt.Errorf("localtransfer: no local route candidate for device %q: not discovered or not policy-approved", opts.PeerDeviceID)
	}

	// Resolve the peer's trusted identity BEFORE dialing: the Opaque
	// handshake will authenticate exactly this device (pair secret bound to
	// the trust-store public key). A revoked or unknown peer never gets a
	// connection attempt.
	rec, err := opts.Store.GetDevice(ctx, opts.PeerDeviceID)
	if err != nil || rec == nil || rec.Revoked {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, fmt.Errorf("localtransfer: peer %q is not a trusted paired device", opts.PeerDeviceID)
	}
	pub, err := hex.DecodeString(rec.PublicKey)
	if err != nil || len(pub) == 0 {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, fmt.Errorf("localtransfer: peer %q has an invalid trust record public key", opts.PeerDeviceID)
	}
	kPair, err := opts.Resolver.ResolvePairSecret(ctx, opts.PeerDeviceID, rec.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, fmt.Errorf("localtransfer: cannot resolve pair secret for %q: %v", opts.PeerDeviceID, err)
	}

	handle := opts.Handle
	if handle == "" {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			opts.Table.MarkFailed(opts.PeerDeviceID)
			return nil, fmt.Errorf("localtransfer: mint handle: %w", err)
		}
		handle = hex.EncodeToString(raw[:])
	}

	// Dial each pinned IP in turn. The IPs were resolved once and
	// policy-approved by discovery; Dial refuses hostnames, so no
	// re-resolution (and no DNS-rebinding window) happens here.
	var sess *localrendezvous.Session
	var dialErrs []string
	for _, ip := range ep.IPs {
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(ep.Port)))
		s, derr := localrendezvous.Dial(ctx, addr, localrendezvous.DialConfig{
			DeviceID:    opts.Identity.DeviceID,
			DialContext: opts.Dial,
		})
		if derr != nil {
			dialErrs = append(dialErrs, addr+": "+derr.Error())
			continue
		}
		sess = s
		break
	}
	if sess == nil {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, fmt.Errorf("localtransfer: no local route to %q (%s)", opts.PeerDeviceID, strings.Join(dialErrs, "; "))
	}
	defer func() { _ = sess.Close() }()

	spec, err := opts.buildSpec(handle, pub, kPair, rec.PairCredentialRef, ep.IPs)
	if err != nil {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, err
	}

	out, err := transfer.Run(ctx, newSessionSignal(sess), spec)
	if err != nil {
		opts.Table.MarkFailed(opts.PeerDeviceID)
		return nil, err
	}
	// The Opaque ceremony authenticated exactly PeerDeviceID: the peer
	// proved knowledge of the pair secret bound to the trust-store public
	// key we resolved above. The selected candidate is verified for that
	// identity — a mismatch would have failed the handshake instead.
	opts.Table.MarkVerified(opts.PeerDeviceID, opts.PeerDeviceID)
	return out, nil
}

// buildSpec assembles the transfer.Spec for the shared engine with the
// local-only invariants baked in. It is a separate function so tests can
// assert the invariants structurally: signaling is supplied by the caller
// (the local session), ICE is host-only, the relay does not exist, and the
// WebRTC candidate policy is pinned to the validated endpoint's IPs.
func (o Options) buildSpec(handle string, peerPub, kPair []byte, credRef string, ips []net.IP) (transfer.Spec, error) {
	if len(peerPub) == 0 || len(kPair) == 0 {
		return transfer.Spec{}, errors.New("localtransfer: missing peer credentials")
	}
	spec := transfer.Spec{
		Opaque: &rendezvous.OpaqueOptions{
			Role:              o.Role,
			Handle:            handle,
			LocalIdentity:     o.Identity,
			PeerDeviceID:      o.PeerDeviceID,
			PeerPublicKey:     peerPub,
			KPair:             kPair,
			PairCredentialRef: credRef,
			// Local-only mode has no rendezvous server: the peers pair
			// directly over the validated TCP transport (ADR 0011). The
			// authentication ceremony itself is unchanged.
			Serverless: true,
		},
		PeerDeviceID: o.PeerDeviceID,
		PeerLabel:    o.PeerLabel,
		Source:       o.Source,
		Sources:      o.Sources,
		DestDir:      o.DestDir,
		Consent:      o.Consent,
		Private:      o.Private,
		// V21-PR07: connect the local path to the existing cross-session
		// resume contract instead of minting a fresh identity per send.
		TransferID:         o.TransferID,
		Resume:             o.Resume,
		OnResume:           o.OnResume,
		OnSendManifest:     o.OnSendManifest,
		OnResumeCredential: o.OnResumeCredential,
		// V22-PR06: the routine origin label rides the wire manifest
		// (offerer); nil for ordinary one-off sends.
		Provenance: o.Provenance,
		// Local-only invariants, enforced on the actual engine — not flags
		// on a UI. Explicit empty ICE servers: host candidates only, no
		// STUN/TURN. DisableRelay: no relay path exists to fall back to.
		// RTCAPI: the ICE agent gathers only within the validated
		// endpoint's networks and rejects outside-policy remote
		// candidates (PR04).
		ICEServers:   []webrtc.ICEServer{},
		DisableRelay: true,
		RTCAPI:       rtc.LocalOnlyAPI(rtc.LocalOnlyNetsForIPs(ips)),
		OnTransport:  o.OnTransport,
		OnProgress:   o.OnProgress,
		OnManifest:   o.OnManifest,
		OnConnect:    o.OnConnect,
	}
	if o.RequirePadding {
		spec.RequirePadding = true
	}
	return spec, nil
}
