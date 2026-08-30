package rendezvous

import "github.com/sendbeam/wire"

// Default caps values. These mirror the protocol constants in
// packages/protocol/src/constants.ts (DEFAULT_FRAME_BYTES, DEFAULT_BLOCK_BYTES); they are
// announced in caps and negotiable, so they are defaults rather than hard limits.
const (
	defaultFrameBytes = 16 * 1024
	defaultBlockBytes = 1024 * 1024
	// capsFrameVersion is the frame-header version byte (FRAME_VERSION in constants.ts).
	capsFrameVersion = 1
)

// Caps is the capability announcement each peer seals as its first frame under the session
// key. Its JSON shape matches CapsPayload in rendezvous.ts, so a browser peer can decode a
// CLI peer's caps and vice versa. Features and SinkHints are always non-nil so they
// serialize as [] (an array), which the TypeScript parser requires.
type Caps struct {
	Version   string   `json:"version"`
	MaxFrame  int      `json:"maxFrame"`
	BlockSize int      `json:"blockSize"`
	Features  []string `json:"features"`
	SinkHints []string `json:"sinkHints"`
}

// FeaturePadding is the capability string announced for wire traffic padding.
const FeaturePadding = wire.PaddingCapability

// DefaultCaps returns the capabilities a CLI peer announces by default.
func DefaultCaps() Caps {
	return Caps{
		Version:   wire.ProtocolVersion,
		MaxFrame:  defaultFrameBytes,
		BlockSize: defaultBlockBytes,
		Features:  []string{"folders", "relay"},
		SinkHints: []string{"direct-file"},
	}
}

// WithPadding returns a clone of c with the padding feature included.
func (c Caps) WithPadding() Caps {
	for _, f := range c.Features {
		if f == FeaturePadding {
			return c
		}
	}
	out := c
	out.Features = append(append([]string(nil), c.Features...), FeaturePadding)
	return out
}

// capsHeader is the fixed frame header for the caps frame: version, Caps type, all
// indices zero. Seal fills in the length.
func capsHeader() wire.FrameHeaderInput {
	return wire.FrameHeaderInput{
		Version: capsFrameVersion,
		Type:    wire.FrameCaps,
	}
}
