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
	"github.com/sendbeam/wire"
)

// buildReceiverSpecWithoutPadding builds the receive spec for a local-only
// joiner whose advertised capabilities deliberately EXCLUDE the padding
// feature — a genuinely padding-incompatible receiver (SB-R07 negative
// fixture).
//
// Why this cannot be expressed through Options/ReceiveOptions today: the
// local path's Opaque ceremony (rendezvous/opaque_session.go) substitutes
// DefaultCaps-derived capabilities — which INCLUDE padding — whenever
// LocalCaps is unset, and buildSpec never sets LocalCaps. So every receiver
// built through ReceiveOptions advertises padding capability by default and
// a strict sender can never observe incompatibility on the local path. The
// wire capability protocol itself is intact (see transfer/padding_test.go);
// this gap is specific to the desktop/local convenience layer.
//
// The spec mirrors ServeSession's joiner construction exactly — trust
// admission, pinned RTC gather, serverless Opaque ceremony, disabled relay —
// except the explicit capability set. Used by the desktop SB-R07 negative
// proof and available to any host needing explicit caps on the local path.
func buildReceiverSpecWithoutPadding(
	ctx context.Context,
	sess *localrendezvous.Session,
	opts ServeOptions,
) (transfer.Spec, error) {
	if opts.Identity == nil {
		return transfer.Spec{}, errors.New("localtransfer: missing local identity")
	}
	if opts.Store == nil {
		return transfer.Spec{}, errors.New("localtransfer: missing trust store")
	}
	if opts.Resolver == nil {
		return transfer.Spec{}, errors.New("localtransfer: missing secret resolver")
	}
	if sess == nil {
		return transfer.Spec{}, errors.New("localtransfer: missing session")
	}
	if opts.DestDir == "" {
		return transfer.Spec{}, errors.New("localtransfer: joiner needs a destination directory")
	}

	peerID := sess.DeviceID
	if peerID == "" {
		return transfer.Spec{}, errors.New("localtransfer: admitted session has no device ID")
	}
	rec, err := opts.Store.GetDevice(ctx, peerID)
	if err != nil || rec == nil || rec.Revoked {
		return transfer.Spec{}, fmt.Errorf("localtransfer: peer %q is not a trusted paired device", peerID)
	}
	pub, err := hex.DecodeString(rec.PublicKey)
	if err != nil || len(pub) == 0 {
		return transfer.Spec{}, fmt.Errorf("localtransfer: peer %q has an invalid trust record public key", peerID)
	}
	kPair, err := opts.Resolver.ResolvePairSecret(ctx, peerID, rec.PairCredentialRef)
	if err != nil || len(kPair) == 0 {
		return transfer.Spec{}, fmt.Errorf("localtransfer: cannot resolve pair secret for %q: %v", peerID, err)
	}

	var ips []net.IP
	if host, _, serr := net.SplitHostPort(sess.RemoteAddr().String()); serr == nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		}
	}
	if host, _, lerr := net.SplitHostPort(sess.LocalAddr().String()); lerr == nil {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		}
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return transfer.Spec{}, fmt.Errorf("localtransfer: mint handle: %w", err)
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
		TransferID:     opts.TransferID,
		Resume:         opts.Resume,
		OnResume:       opts.OnResume,
		Dial:           opts.Dial,
		OnTransport:    opts.OnTransport,
		OnProgress:     opts.OnProgress,
		OnManifest:     opts.OnManifest,
		OnConnect:      opts.OnConnect,
	}
	spec, err := o.buildSpec(handle, pub, kPair, rec.PairCredentialRef, ips)
	if err != nil {
		return transfer.Spec{}, err
	}
	// THE FIXTURE POINT: replace the Opaque local capabilities with an
	// explicit set that EXCLUDES the padding feature. This is the only
	// difference from the compatible receiver construction.
	spec.Opaque.LocalCaps = []string{"transfer.v1", "folders", "rendezvous", "resume", wire.HandoffCapability}
	return spec, nil
}

// ReceiveWithoutPaddingCapability accepts the next paired session on
// opts.Server and runs one local-only transfer as joiner with the receiver's
// advertised capabilities explicitly EXCLUDING the padding feature (SB-R07
// negative fixture; see buildReceiverSpecWithoutPadding for the rationale).
// Admission, authentication and every other behavior are identical to
// Receive.
func ReceiveWithoutPaddingCapability(ctx context.Context, opts ReceiveOptions) (*transfer.Outcome, error) {
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

	spec, err := buildReceiverSpecWithoutPadding(ctx, sess, ServeOptions{
		Identity:       opts.Identity,
		Store:          opts.Store,
		Resolver:       opts.Resolver,
		DestDir:        opts.DestDir,
		Consent:        opts.Consent,
		RequirePadding: opts.RequirePadding,
		Private:        opts.Private,
		TransferID:     opts.TransferID,
		Resume:         opts.Resume,
		OnResume:       opts.OnResume,
		Dial:           opts.Dial,
		OnTransport:    opts.OnTransport,
		OnProgress:     opts.OnProgress,
		OnManifest:     opts.OnManifest,
		OnConnect:      opts.OnConnect,
	})
	if err != nil {
		return nil, err
	}
	out, err := transfer.Run(ctx, newSessionSignal(sess), spec)
	if err != nil {
		return nil, fmt.Errorf("localtransfer: receive failed: %w", err)
	}
	return out, nil
}
