// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localtransfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ReceiveOptions configures one local-only receive: the host accepts the
// next paired session on an already-started local rendezvous server and runs
// the shared encrypted transfer engine as joiner (V21-PR06).
type ReceiveOptions struct {
	// Identity is the local device identity used in the Opaque handshake.
	Identity *wire.DeviceIdentity
	// Store is the trust store: peer admission and peer public-key lookup.
	Store trust.Store
	// Resolver resolves the k_pair secret for the peer device.
	Resolver trust.SecretResolver
	// Server is the started local rendezvous server. Paired dialers are
	// admitted via the trust store; no pairing window is opened here.
	Server *localrendezvous.Server
	// DestDir receives files.
	DestDir string
	// Consent evaluates the incoming transfer. Nil accepts into DestDir per
	// the engine default; pass an explicit handler to prompt.
	Consent transfer.ConsentHandler

	// RequirePadding enforces the traffic-padding policy; Private negotiates
	// padding. Both are passed straight to the shared engine.
	RequirePadding bool
	Private        bool

	// Dial performs the TCP dial for any outbound connection (normally nil
	// here; the joiner only accepts). Provided for egress monitoring.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// OnTransport reports the selected byte path ("direct" in local-only).
	OnTransport func(string)
	// OnProgress reports cumulative bytes acknowledged after verify-and-sink.
	OnProgress func(int64)
	// OnManifest fires when the sender's manifest arrives.
	OnManifest func(wire.FileEntry)
	// OnConnect fires once the data channel opens, before bytes move.
	OnConnect func()
}

// ServeOptions is ReceiveOptions without the server: it drives one receive
// on an already-admitted session (used by hosts, like the desktop, that own
// their accept loop).
type ServeOptions struct {
	Identity       *wire.DeviceIdentity
	Store          trust.Store
	Resolver       trust.SecretResolver
	DestDir        string
	Consent        transfer.ConsentHandler
	RequirePadding bool
	Private        bool
	Dial           func(ctx context.Context, network, address string) (net.Conn, error)
	OnTransport    func(string)
	OnProgress     func(int64)
	OnManifest     func(wire.FileEntry)
	OnConnect      func()
}

// Receive accepts the next paired session on opts.Server and runs one
// local-only transfer as joiner. Only sessions the rendezvous server admits
// (paired, non-revoked devices per the trust store) are accepted; the Opaque
// ceremony then authenticates exactly the claimed device ID before any bytes
// move. There is no online fallback at any step.
func Receive(ctx context.Context, opts ReceiveOptions) (*transfer.Outcome, error) {
	// Validate everything before waiting for a session: a caller bug must
	// fail fast, never hang on the accept.
	if opts.Identity == nil {
		return nil, errors.New("localtransfer: missing local identity")
	}
	if opts.Store == nil {
		return nil, errors.New("localtransfer: missing trust store")
	}
	if opts.Resolver == nil {
		return nil, errors.New("localtransfer: missing secret resolver")
	}
	if opts.Server == nil {
		return nil, errors.New("localtransfer: missing rendezvous server")
	}
	if opts.DestDir == "" {
		return nil, errors.New("localtransfer: joiner needs a destination directory")
	}

	// Wait for the next admitted session. Only the first is taken; later
	// sessions are closed so one Receive call serves exactly one transfer.
	sessCh := make(chan *localrendezvous.Session, 1)
	opts.Server.OnSession(func(s *localrendezvous.Session) {
		select {
		case sessCh <- s:
		default:
			_ = s.Close()
		}
	})

	var sess *localrendezvous.Session
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("localtransfer: receive cancelled: %w", ctx.Err())
	case sess = <-sessCh:
	}
	defer func() { _ = sess.Close() }()

	return ServeSession(ctx, sess, ServeOptions{
		Identity:       opts.Identity,
		Store:          opts.Store,
		Resolver:       opts.Resolver,
		DestDir:        opts.DestDir,
		Consent:        opts.Consent,
		RequirePadding: opts.RequirePadding,
		Private:        opts.Private,
		Dial:           opts.Dial,
		OnTransport:    opts.OnTransport,
		OnProgress:     opts.OnProgress,
		OnManifest:     opts.OnManifest,
		OnConnect:      opts.OnConnect,
	})
}

// ServeSession runs one local-only receive on an already-admitted session.
// The session was admitted by the rendezvous server, but admission is not
// authentication: the peer's trust record and pair secret are resolved and
// the Opaque ceremony authenticates exactly the claimed device ID before any
// bytes move. A revoked or unknown device never reaches the transfer engine.
func ServeSession(ctx context.Context, sess *localrendezvous.Session, opts ServeOptions) (*transfer.Outcome, error) {
	if opts.Identity == nil {
		return nil, errors.New("localtransfer: missing local identity")
	}
	if opts.Store == nil {
		return nil, errors.New("localtransfer: missing trust store")
	}
	if opts.Resolver == nil {
		return nil, errors.New("localtransfer: missing secret resolver")
	}
	if sess == nil {
		return nil, errors.New("localtransfer: missing session")
	}
	if opts.DestDir == "" {
		return nil, errors.New("localtransfer: joiner needs a destination directory")
	}

	peerID := sess.DeviceID
	if peerID == "" {
		return nil, errors.New("localtransfer: admitted session has no device ID")
	}
	rec, err := opts.Store.GetDevice(ctx, peerID)
	if err != nil || rec == nil || rec.Revoked {
		return nil, fmt.Errorf("localtransfer: peer %q is not a trusted paired device", peerID)
	}
	pub, err := hex.DecodeString(rec.PublicKey)
	if err != nil || len(pub) == 0 {
		return nil, fmt.Errorf("localtransfer: peer %q has an invalid trust record public key", peerID)
	}
	kPair, err := opts.Resolver.ResolvePairSecret(ctx, peerID, rec.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		return nil, fmt.Errorf("localtransfer: cannot resolve pair secret for %q: %v", peerID, err)
	}

	// Pin the WebRTC data path to the session's remote network: the
	// joiner's data channel may only use the validated local peer address.
	var ips []net.IP
	if host, _, serr := net.SplitHostPort(sess.RemoteAddr().String()); serr == nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		}
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("localtransfer: mint handle: %w", err)
	}
	handle := hex.EncodeToString(raw[:])

	o := Options{
		Identity:       opts.Identity,
		Store:          opts.Store,
		Resolver:       opts.Resolver,
		Role:           rendezvous.RoleJoiner,
		PeerDeviceID:   peerID,
		PeerLabel:      peerID,
		DestDir:        opts.DestDir,
		Consent:        opts.Consent,
		RequirePadding: opts.RequirePadding,
		Private:        opts.Private,
		Dial:           opts.Dial,
		OnTransport:    opts.OnTransport,
		OnProgress:     opts.OnProgress,
		OnManifest:     opts.OnManifest,
		OnConnect:      opts.OnConnect,
	}
	spec, err := o.buildSpec(handle, pub, kPair, rec.PairCredentialRef, ips)
	if err != nil {
		return nil, err
	}
	out, err := transfer.Run(ctx, newSessionSignal(sess), spec)
	if err != nil {
		return nil, fmt.Errorf("localtransfer: receive failed: %w", err)
	}
	return out, nil
}
