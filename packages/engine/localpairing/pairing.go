// Package localpairing performs first-time offline pairing over the
// bounded local rendezvous service for SendBeam v2.1 "Nearby & Offline"
// (ADR 0011, V21-PR05).
//
// A fresh pair — devices never enrolled online — can bootstrap trust
// without any public service. The inviter opens a short-lived pairing
// window on its local rendezvous server and shares an invitation
// out-of-band (QR code). The joiner dials the pinned literal IP
// with the window token; both sides then run the existing reviewed
// pairing ceremony (trust.PairingCoordinator) over the session. Trust
// and credentials persist only after mutual confirmation.
//
// Invitation contents are bootstrap data only: address, window token,
// inviter fingerprint, the ceremony master key, expiry. The token is a
// 128-bit random value; guessing is rate-limited by the server's
// per-IP budget. The recipient verifies the inviter's actual device
// identity (fingerprint), not a spoofable label.
//
// The ceremony master key is a fresh 256-bit secret per invitation,
// carried in the invitation itself so the joiner learns it out-of-band
// together with the address and window token. Because the key is
// high-entropy, QR/scan is the supported exchange path; typing it
// out would mean transcribing 64 hex characters.
package localpairing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/trust"
)

// invitationVersion is the invitation encoding version.
const invitationVersion = "v1"

// masterKeyBytes is the size of the ceremony master key in bytes.
const masterKeyBytes = 32

// Invitation is the out-of-band bootstrap for one offline pairing.
// It is safe to display as a QR code (or read aloud as a code); it
// carries only a short-lived window token and the per-invitation
// ceremony master key, never a long-term secret.
type Invitation struct {
	// Address is the inviter's rendezvous "ip:port" (literal IP, no DNS).
	Address string
	// Token is the pairing-window token (128-bit hex).
	Token string
	// Fingerprint is the inviter's device ID, which the joiner verifies
	// against the ceremony's authenticated identity.
	Fingerprint string
	// MasterKeyHex is the hex-encoded fresh 256-bit ceremony master
	// key for this invitation. The inviter generates it; the joiner
	// learns it from the invitation (QR) out-of-band.
	MasterKeyHex string
	// ExpiresAt is the window expiry (informational; the server enforces it).
	ExpiresAt time.Time
}

// MasterKey decodes the invitation's ceremony master key.
func (in Invitation) MasterKey() ([]byte, error) {
	raw, err := hex.DecodeString(in.MasterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("localpairing: bad master key encoding: %w", err)
	}
	if len(raw) != masterKeyBytes {
		return nil, fmt.Errorf("localpairing: master key must be %d bytes, got %d", masterKeyBytes, len(raw))
	}
	return raw, nil
}

// Encode renders the invitation as a single scannable string.
// Format: sendbeam-local-pair|v1|<address>|<token>|<fingerprint>|<masterkeyhex>
// ("|" separates fields so IPv6 addresses and host:port pairs survive.)
func (in Invitation) Encode() string {
	return strings.Join([]string{
		"sendbeam-local-pair", invitationVersion,
		in.Address, in.Token, in.Fingerprint, in.MasterKeyHex,
	}, "|")
}

// ParseInvitation decodes an invitation string. It rejects malformed,
// wrong-version, or empty-field invitations without network activity.
func ParseInvitation(s string) (*Invitation, error) {
	parts := strings.Split(s, "|")
	if len(parts) != 6 {
		return nil, errors.New("localpairing: malformed invitation")
	}
	if parts[0] != "sendbeam-local-pair" || parts[1] != invitationVersion {
		return nil, errors.New("localpairing: unsupported invitation version")
	}
	in := &Invitation{
		Address:      parts[2],
		Token:        parts[3],
		Fingerprint:  parts[4],
		MasterKeyHex: parts[5],
	}
	if in.Address == "" || in.Token == "" || in.Fingerprint == "" || in.MasterKeyHex == "" {
		return nil, errors.New("localpairing: invitation has empty fields")
	}
	// Literal IP required: no DNS at parse time (rebinding defense).
	host, _, err := net.SplitHostPort(in.Address)
	if err != nil {
		return nil, fmt.Errorf("localpairing: bad invitation address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("localpairing: invitation address must be a literal IP")
	}
	if _, err := in.MasterKey(); err != nil {
		return nil, err
	}
	return in, nil
}

// CreateInvitation opens a pairing window on the server and returns the
// invitation to share out-of-band. The fingerprint is the inviter's
// device ID (the cryptographic identity the ceremony authenticates, not
// a spoofable label). The ceremony master key is a fresh 256-bit
// secret generated per invitation (never the window token: the token
// admits to the session, the master key authenticates the ceremony) and
// is carried in the invitation so the joiner learns it out-of-band.
// The inviter recovers the raw key with inv.MasterKey(). Callers must
// not log it.
func CreateInvitation(srv *localrendezvous.Server, address, fingerprint string, window time.Duration) (*Invitation, error) {
	if srv == nil {
		return nil, errors.New("localpairing: server required")
	}
	token := srv.OpenPairingWindow(window)
	if token == "" {
		return nil, errors.New("localpairing: could not open pairing window")
	}
	key, err := newMasterKey()
	if err != nil {
		return nil, fmt.Errorf("localpairing: could not generate master key: %w", err)
	}
	return &Invitation{
		Address:      address,
		Token:        token,
		Fingerprint:  fingerprint,
		MasterKeyHex: hex.EncodeToString(key),
		ExpiresAt:    time.Now().Add(window),
	}, nil
}

// Options configures one side of the offline pairing.
type Options struct {
	// Coordinator runs the reviewed pairing ceremony.
	Coordinator *trust.PairingCoordinator
	// DeviceName is the local display name offered to the peer.
	DeviceName string
	// MasterKey is the pairing secret. For offline pairing it is the
	// invitation's ceremony master key: the inviter recovers it with
	// inv.MasterKey(), the joiner recovers it from the parsed
	// invitation. It is never the window token: the token admits to
	// the session, the master key authenticates the ceremony. Callers
	// must not log it.
	MasterKey []byte
	// Dial performs the TCP dial for Join. Nil uses a default dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// OnSession, for Accept, optionally observes the admitted session
	// before the ceremony runs (e.g. to show "peer connecting").
	OnSession func(*localrendezvous.Session)
}

// newMasterKey generates a fresh 256-bit pairing secret.
func newMasterKey() ([]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	return raw[:], nil
}
