package rendezvous

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// OpaquePhase represents the current phase in an opaque rendezvous session.
type OpaquePhase string

// Opaque handshake phases.
const (
	OpaquePhaseIdle           OpaquePhase = "idle"
	OpaquePhaseRendezvousSent OpaquePhase = "rendezvous_sent"
	OpaquePhaseWaitingPeer    OpaquePhase = "waiting_peer"
	OpaquePhasePaired         OpaquePhase = "paired"
	OpaquePhaseAuthenticating OpaquePhase = "authenticating"
	OpaquePhaseEstablished    OpaquePhase = "established"
	OpaquePhaseFailed         OpaquePhase = "failed"
)

// OpaqueResult contains the output of a successfully completed opaque rendezvous session.
type OpaqueResult struct {
	Role           Role
	Handle         string
	PeerDeviceID   string
	Master         []byte
	SendKey        []byte
	RecvKey        []byte
	NegotiatedCaps []string
}

// OpaqueOptions configures an opaque rendezvous session.
type OpaqueOptions struct {
	Role              Role
	Handle            string
	LocalIdentity     *wire.DeviceIdentity
	PeerDeviceID      string
	PeerPublicKey     ed25519.PublicKey
	KPair             []byte
	PairCredentialRef string
	LocalCaps         []string
	Transport         Sink
	OnPhase           func(OpaquePhase)
	ReplayCache       *wire.NonceReplayCache
	Tombstones        trust.TombstoneStore
	TrustStore        trust.Store
}

// OpaqueSession drives the sendbeam/3 authenticated session handshake over an opaque rendezvous channel.
type OpaqueSession struct {
	opts   OpaqueOptions
	phase  OpaquePhase
	mu     sync.Mutex
	done   chan struct{}
	result *OpaqueResult
	err    error

	privKey  *ecdh.PrivateKey
	pubBytes []byte
	nonce    []byte
	initMsg  *wire.TrustedAuthInit
	master   []byte
	sendKey  []byte
	recvKey  []byte
	negCaps  []string
	selfConf bool
	peerConf bool
}

// NewOpaqueSession creates a new OpaqueSession.
func NewOpaqueSession(opts OpaqueOptions) *OpaqueSession {
	return &OpaqueSession{
		opts:  opts,
		phase: OpaquePhaseIdle,
		done:  make(chan struct{}),
	}
}

// Phase returns the session's current phase.
func (s *OpaqueSession) Phase() OpaquePhase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

func (s *OpaqueSession) setPhaseLocked(phase OpaquePhase) {
	s.phase = phase
	if s.opts.OnPhase != nil {
		s.opts.OnPhase(phase)
	}
}

// Start begins the opaque rendezvous session by validating the handle and sending a rendezvous message.
func (s *OpaqueSession) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase != OpaquePhaseIdle {
		return nil
	}
	if !wire.ValidateRendezvousHandle(s.opts.Handle) {
		return s.failLocked(errors.New("invalid_handle"))
	}
	if s.opts.LocalIdentity == nil {
		return s.failLocked(errors.New("local identity required"))
	}
	if len(s.opts.PeerPublicKey) != ed25519.PublicKeySize {
		return s.failLocked(wire.ErrInvalidPublicKey)
	}
	if len(s.opts.KPair) == 0 {
		return s.failLocked(errors.New("k_pair required"))
	}

	// Check tombstones if store is present
	if s.opts.Tombstones != nil && s.opts.Tombstones.HasTombstone(context.Background(), s.opts.PeerDeviceID) {
		return s.failLocked(wire.ErrTrustedPeerRevoked)
	}

	s.setPhaseLocked(OpaquePhaseRendezvousSent)
	return s.opts.Transport.Send(NewRendezvous(s.opts.Handle, string(s.opts.Role)))
}

// Resume attempts to re-attach to an existing handle room after disconnect.
func (s *OpaqueSession) Resume() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !wire.ValidateRendezvousHandle(s.opts.Handle) {
		return s.failLocked(errors.New("invalid_handle"))
	}
	return s.opts.Transport.Send(NewResume(s.opts.Handle, string(s.opts.Role)))
}

// Handle processes an incoming signaling frame.
func (s *OpaqueSession) Handle(m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.phase == OpaquePhaseFailed || s.phase == OpaquePhaseEstablished {
		return nil
	}

	switch m.Type {
	case typeCreated:
		if s.phase == OpaquePhaseRendezvousSent {
			s.setPhaseLocked(OpaquePhaseWaitingPeer)
		}
		return nil

	case typePeerJoined, typePeerRejoined:
		return s.onPairedLocked()

	case typeResumed:
		return nil

	case typePeerLeft:
		return s.failLocked(errors.New("peer_left"))

	case typeError:
		code := m.Code
		if code == "" {
			code = "signaling_error"
		}
		return s.failLocked(fmt.Errorf("signaling error: %s", code))

	case typeTrustedAuthInit:
		return s.onTrustedAuthInitLocked(m)

	case typeTrustedAuthResponse:
		return s.onTrustedAuthResponseLocked(m)

	case typeTrustedAuthConfirm:
		return s.onTrustedAuthConfirmLocked(m)

	default:
		return nil
	}
}

func (s *OpaqueSession) onPairedLocked() error {
	s.setPhaseLocked(OpaquePhaseAuthenticating)
	if s.opts.Role == RoleOfferer {
		privA, pubA, err := wire.GenerateX25519KeyPair()
		if err != nil {
			return s.failLocked(err)
		}
		s.privKey = privA
		s.pubBytes = pubA

		nonceA := make([]byte, wire.TrustedAuthNonceSize)
		if _, err := io.ReadFull(rand.Reader, nonceA); err != nil {
			return s.failLocked(err)
		}
		s.nonce = nonceA

		caps := s.opts.LocalCaps
		if len(caps) == 0 {
			caps = []string{"transfer.v1", "padding"}
		}

		var revocations []wire.RevocationRecord
		if s.opts.TrustStore != nil {
			if stored, err := s.opts.TrustStore.ListRevocations(context.Background()); err == nil {
				for _, r := range stored {
					if r != nil {
						revocations = append(revocations, *r)
					}
				}
			}
		}

		initMsg, err := wire.NewTrustedAuthInitV3(
			s.opts.LocalIdentity,
			s.opts.PeerDeviceID,
			s.opts.PairCredentialRef,
			s.opts.KPair,
			caps,
			pubA,
			nonceA,
			time.Now().UTC(),
			revocations,
		)
		if err != nil {
			return s.failLocked(err)
		}
		s.initMsg = initMsg

		data, err := wire.EncodeTrustedAuthMessage(initMsg)
		if err != nil {
			return s.failLocked(err)
		}
		return s.opts.Transport.Send(Message{Type: typeTrustedAuthInit, Raw: data})
	}
	return nil
}

func (s *OpaqueSession) onTrustedAuthInitLocked(m Message) error {
	if s.opts.Role != RoleJoiner {
		return nil
	}

	rawData := m.Raw
	if len(rawData) == 0 {
		var err error
		rawData, err = json.Marshal(m)
		if err != nil {
			return s.failLocked(err)
		}
	}

	decoded, err := wire.DecodeTrustedAuthMessage(rawData)
	if err != nil {
		return s.failLocked(err)
	}
	initMsg, ok := decoded.(*wire.TrustedAuthInit)
	if !ok {
		return s.failLocked(wire.ErrInvalidTrustedMessage)
	}
	s.initMsg = initMsg

	now := time.Now().UTC()
	peerEphemPub, peerNonce, err := wire.VerifyTrustedAuthInitV3(initMsg, s.opts.KPair, s.opts.PeerPublicKey, s.opts.LocalIdentity.DeviceID, now)
	if err != nil {
		return s.failLocked(err)
	}
	if s.opts.ReplayCache != nil {
		if err := s.opts.ReplayCache.CheckAndRecord(initMsg.InitiatorDeviceID, initMsg.Nonce, now); err != nil {
			return s.failLocked(err)
		}
	}

	privB, pubB, err := wire.GenerateX25519KeyPair()
	if err != nil {
		return s.failLocked(err)
	}

	nonceB := make([]byte, wire.TrustedAuthNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceB); err != nil {
		return s.failLocked(err)
	}

	localCaps := s.opts.LocalCaps
	if len(localCaps) == 0 {
		localCaps = []string{"transfer.v1", "padding"}
	}

	var revocations []wire.RevocationRecord
	if s.opts.TrustStore != nil {
		if stored, err := s.opts.TrustStore.ListRevocations(context.Background()); err == nil {
			for _, r := range stored {
				if r != nil {
					revocations = append(revocations, *r)
				}
			}
		}
	}

	respMsg, err := wire.NewTrustedAuthResponseV3(s.opts.LocalIdentity, initMsg, s.opts.KPair, localCaps, pubB, nonceB, revocations)
	if err != nil {
		return s.failLocked(err)
	}

	respData, err := wire.EncodeTrustedAuthMessage(respMsg)
	if err != nil {
		return s.failLocked(err)
	}
	if err := s.opts.Transport.Send(Message{Type: typeTrustedAuthResponse, Raw: respData}); err != nil {
		return s.failLocked(err)
	}

	ssECDH, err := wire.ComputeX25519SharedSecret(privB, peerEphemPub)
	if err != nil {
		return s.failLocked(err)
	}
	defer wire.ZeroizeBytes(ssECDH)

	keys, err := wire.DeriveTrustedSessionKeysV3(s.opts.KPair, ssECDH, peerEphemPub, pubB, peerNonce, nonceB, initMsg.InitiatorDeviceID, s.opts.LocalIdentity.DeviceID, initMsg.Capabilities, localCaps)
	if err != nil {
		return s.failLocked(err)
	}

	s.master = keys.SessionMaster
	// Joiner (responder): send is r2i, recv is i2r
	s.sendKey = keys.ResponderToInitiatorKey
	s.recvKey = keys.InitiatorToResponderKey
	s.negCaps = keys.NegotiatedCapabilities

	confMsg := wire.NewTrustedAuthConfirm(s.master, wire.DomainTrustedConfirmResp3, s.opts.LocalIdentity.DeviceID, true)
	confData, err := wire.EncodeTrustedAuthMessage(confMsg)
	if err != nil {
		return s.failLocked(err)
	}
	s.selfConf = true
	if err := s.opts.Transport.Send(Message{Type: typeTrustedAuthConfirm, Raw: confData}); err != nil {
		return s.failLocked(err)
	}

	return s.checkEstablishedLocked()
}

func (s *OpaqueSession) onTrustedAuthResponseLocked(m Message) error {
	if s.opts.Role != RoleOfferer || s.initMsg == nil || s.privKey == nil {
		return nil
	}

	rawData := m.Raw
	if len(rawData) == 0 {
		var err error
		rawData, err = json.Marshal(m)
		if err != nil {
			return s.failLocked(err)
		}
	}

	decoded, err := wire.DecodeTrustedAuthMessage(rawData)
	if err != nil {
		return s.failLocked(err)
	}
	respMsg, ok := decoded.(*wire.TrustedAuthResponse)
	if !ok {
		return s.failLocked(wire.ErrInvalidTrustedMessage)
	}

	peerEphemPub, peerNonce, err := wire.VerifyTrustedAuthResponseV3(respMsg, s.initMsg, s.opts.KPair, s.opts.PeerPublicKey, s.opts.LocalIdentity.DeviceID)
	if err != nil {
		return s.failLocked(err)
	}
	if s.opts.ReplayCache != nil {
		if err := s.opts.ReplayCache.CheckAndRecord(respMsg.ResponderDeviceID, respMsg.Nonce, time.Now().UTC()); err != nil {
			return s.failLocked(err)
		}
	}

	ssECDH, err := wire.ComputeX25519SharedSecret(s.privKey, peerEphemPub)
	if err != nil {
		return s.failLocked(err)
	}
	s.privKey = nil
	defer wire.ZeroizeBytes(ssECDH)

	keys, err := wire.DeriveTrustedSessionKeysV3(s.opts.KPair, ssECDH, s.pubBytes, peerEphemPub, s.nonce, peerNonce, s.opts.LocalIdentity.DeviceID, s.opts.PeerDeviceID, s.initMsg.Capabilities, respMsg.Capabilities)
	if err != nil {
		return s.failLocked(err)
	}

	s.master = keys.SessionMaster
	// Offerer (initiator): send is i2r, recv is r2i
	s.sendKey = keys.InitiatorToResponderKey
	s.recvKey = keys.ResponderToInitiatorKey
	s.negCaps = keys.NegotiatedCapabilities

	confMsg := wire.NewTrustedAuthConfirm(s.master, wire.DomainTrustedConfirmInit3, s.opts.LocalIdentity.DeviceID, true)
	confData, err := wire.EncodeTrustedAuthMessage(confMsg)
	if err != nil {
		return s.failLocked(err)
	}
	s.selfConf = true
	if err := s.opts.Transport.Send(Message{Type: typeTrustedAuthConfirm, Raw: confData}); err != nil {
		return s.failLocked(err)
	}

	return s.checkEstablishedLocked()
}

func (s *OpaqueSession) onTrustedAuthConfirmLocked(m Message) error {
	if len(s.master) == 0 {
		return s.failLocked(errors.New("session master missing"))
	}

	rawData := m.Raw
	if len(rawData) == 0 {
		var err error
		rawData, err = json.Marshal(m)
		if err != nil {
			return s.failLocked(err)
		}
	}

	decoded, err := wire.DecodeTrustedAuthMessage(rawData)
	if err != nil {
		return s.failLocked(err)
	}
	confMsg, ok := decoded.(*wire.TrustedAuthConfirm)
	if !ok {
		return s.failLocked(wire.ErrInvalidTrustedMessage)
	}

	domain := wire.DomainTrustedConfirmResp3
	if s.opts.Role == RoleJoiner {
		domain = wire.DomainTrustedConfirmInit3
	}

	if err := wire.VerifyTrustedAuthConfirm(confMsg, s.master, domain, s.opts.PeerDeviceID); err != nil {
		return s.failLocked(err)
	}

	s.peerConf = true
	return s.checkEstablishedLocked()
}

func (s *OpaqueSession) checkEstablishedLocked() error {
	if s.selfConf && s.peerConf && len(s.master) > 0 && len(s.sendKey) > 0 && len(s.recvKey) > 0 {
		s.setPhaseLocked(OpaquePhaseEstablished)
		s.result = &OpaqueResult{
			Role:           s.opts.Role,
			Handle:         s.opts.Handle,
			PeerDeviceID:   s.opts.PeerDeviceID,
			Master:         s.master,
			SendKey:        s.sendKey,
			RecvKey:        s.recvKey,
			NegotiatedCaps: s.negCaps,
		}
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
	return nil
}

func (s *OpaqueSession) failLocked(err error) error {
	s.privKey = nil
	s.setPhaseLocked(OpaquePhaseFailed)
	s.err = err
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return err
}

// Wait blocks until the handshake finishes (either established or failed) and returns the result.
func (s *OpaqueSession) Wait() (*OpaqueResult, error) {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

// Result returns the result if established, or nil if still in flight or failed.
func (s *OpaqueSession) Result() (*OpaqueResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}
