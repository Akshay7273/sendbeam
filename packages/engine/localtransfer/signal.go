package localtransfer

import (
	"context"
	"errors"
	"fmt"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/rendezvous"
)

// Frame types multiplexing the transfer signal protocol over one local
// rendezvous session. The WebSocket transport distinguishes text (signaling)
// from binary (relay) frames by frame type; the length-prefixed session has
// no such distinction, so the adapter tags each frame explicitly.
const (
	frameSignal = 0x00 // JSON-encoded rendezvous.Message
	frameBinary = 0x01 // opaque binary payload (relay frames)
)

// sessionSignal adapts a *localrendezvous.Session to transfer.Signal, the
// socket the transfer driver adopts for the whole exchange: handshake,
// SDP/ICE, and (when enabled) relay frames. Both peers must use this adapter
// (or an identical framing); frames from any other writer are rejected.
type sessionSignal struct {
	sess *localrendezvous.Session
}

// newSessionSignal wraps an admitted local rendezvous session as the
// transfer signal transport.
func newSessionSignal(sess *localrendezvous.Session) *sessionSignal {
	return &sessionSignal{sess: sess}
}

// Send writes one signaling message as a tagged JSON frame.
func (s *sessionSignal) Send(m rendezvous.Message) error {
	raw, err := rendezvous.MarshalMessage(m)
	if err != nil {
		return fmt.Errorf("localtransfer: marshal signal message: %w", err)
	}
	frame := make([]byte, 0, len(raw)+1)
	frame = append(frame, frameSignal)
	frame = append(frame, raw...)
	return s.sess.WriteFrame(context.Background(), frame)
}

// SendBinary writes one opaque binary frame.
func (s *sessionSignal) SendBinary(frame []byte) error {
	out := make([]byte, 0, len(frame)+1)
	out = append(out, frameBinary)
	out = append(out, frame...)
	return s.sess.WriteFrame(context.Background(), out)
}

// Run pumps inbound frames until ctx ends or the session fails. Malformed or
// mistyped frames fail the run: the driver treats that as a handshake or
// transport failure and fails the transfer closed.
func (s *sessionSignal) Run(ctx context.Context, onMessage func(rendezvous.Message), onBinary func([]byte)) error {
	for {
		frame, err := s.sess.ReadFrame(ctx)
		if err != nil {
			return err
		}
		if len(frame) == 0 {
			return errors.New("localtransfer: empty signal frame")
		}
		switch frame[0] {
		case frameSignal:
			msg, err := rendezvous.UnmarshalMessage(frame[1:])
			if err != nil {
				return fmt.Errorf("localtransfer: malformed signal frame: %w", err)
			}
			onMessage(msg)
		case frameBinary:
			if onBinary == nil {
				return errors.New("localtransfer: unexpected binary frame")
			}
			onBinary(frame[1:])
		default:
			return fmt.Errorf("localtransfer: unknown signal frame type %#02x", frame[0])
		}
	}
}

// Close terminates the underlying session.
func (s *sessionSignal) Close() {
	_ = s.sess.Close()
}
