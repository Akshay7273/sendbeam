// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localpairing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/trust"
)

// Accept waits for one pairing session on the server and runs the
// acceptor side of the reviewed ceremony. It returns the established
// trust result; trust persists only after mutual confirmation inside
// the coordinator.
//
// The invitation's window token admits the joiner to the session (via
// the server's pairing window); the ceremony's master key authenticates
// the peer. A wrong token never reaches the ceremony: the server refuses
// the hello.
//
// Only the first pairing-kind session is consumed; competing joiners
// get their own sessions and fail the ceremony independently (the
// coordinator never leaves partial trust).
func Accept(ctx context.Context, srv *localrendezvous.Server, o Options) (*trust.PairingResult, error) {
	if srv == nil {
		return nil, errors.New("localpairing: server required")
	}
	if o.Coordinator == nil {
		return nil, errors.New("localpairing: coordinator required")
	}
	if len(o.MasterKey) == 0 {
		return nil, errors.New("localpairing: master key required")
	}

	sessCh := make(chan *localrendezvous.Session, 1)
	srv.OnSession(func(sess *localrendezvous.Session) {
		if sess.Kind != localrendezvous.PeerPairing {
			return
		}
		select {
		case sessCh <- sess:
		default:
			// A competing joiner arrived while one is in progress: close
			// it so it fails cleanly instead of hanging the ceremony.
			_ = sess.Close()
		}
	})

	var sess *localrendezvous.Session
	select {
	case sess = <-sessCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if o.OnSession != nil {
		o.OnSession(sess)
	}
	defer func() { _ = sess.Close() }()

	cfg := trust.PairingSessionConfig{
		DeviceName: o.DeviceName,
		MasterKey:  o.MasterKey,
	}
	res, err := o.Coordinator.AcceptPairing(ctx, sess.PairingTransport(), cfg)
	if err != nil {
		return nil, fmt.Errorf("localpairing: accept ceremony: %w", err)
	}
	return res, nil
}

// Join dials the inviter's rendezvous with the invitation token and runs
// the initiator side of the reviewed ceremony. It verifies the peer's
// authenticated device ID against the invitation fingerprint: a
// substituted endpoint or spoofed identity fails closed with no trust
// persisted.
func Join(ctx context.Context, in *Invitation, o Options) (*trust.PairingResult, error) {
	if in == nil {
		return nil, errors.New("localpairing: invitation required")
	}
	if o.Coordinator == nil {
		return nil, errors.New("localpairing: coordinator required")
	}
	if len(o.MasterKey) == 0 {
		return nil, errors.New("localpairing: master key required")
	}
	if time.Now().After(in.ExpiresAt) {
		return nil, errors.New("localpairing: invitation expired")
	}

	dial := o.Dial
	if dial == nil {
		dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	sess, err := localrendezvous.Dial(ctx, in.Address, localrendezvous.DialConfig{
		DeviceID:    o.DeviceName,
		PairToken:   in.Token,
		DialContext: dial,
	})
	if err != nil {
		return nil, fmt.Errorf("localpairing: dial inviter: %w", err)
	}
	defer func() { _ = sess.Close() }()

	cfg := trust.PairingSessionConfig{
		DeviceName: o.DeviceName,
		MasterKey:  o.MasterKey,
	}
	res, err := o.Coordinator.InitiatePairing(ctx, sess.PairingTransport(), cfg)
	if err != nil {
		return nil, fmt.Errorf("localpairing: join ceremony: %w", err)
	}
	// Identity confirmation: the ceremony authenticated a device ID; it
	// must match the invitation fingerprint. A substituted endpoint that
	// completes the ceremony with a different identity fails here, before
	// the caller can use the result. The just-persisted trust record is
	// rolled back so no usable partial trust remains.
	if res.PeerRecord == nil || res.PeerRecord.DeviceID != in.Fingerprint {
		if res.PeerRecord != nil {
			_ = o.Coordinator.UnpairDevice(ctx, res.PeerRecord.DeviceID)
		}
		return nil, errors.New("localpairing: peer identity does not match invitation fingerprint")
	}
	return res, nil
}
