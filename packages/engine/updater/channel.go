package updater

import (
	"fmt"
	"strings"
)

// Channel represents an update distribution channel.
type Channel string

const (
	// ChannelStable is the default official release channel (stable tags only).
	ChannelStable Channel = "stable"
	// ChannelBeta is the early-access candidate release channel (stable + beta / RC tags).
	ChannelBeta Channel = "beta"
	// ChannelDev tracks local or development builds.
	ChannelDev Channel = "dev"
)

// ParseChannel parses a channel string.
func ParseChannel(s string) (Channel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "stable", "":
		return ChannelStable, nil
	case "beta", "candidate", "rc":
		return ChannelBeta, nil
	case "dev", "development":
		return ChannelDev, nil
	default:
		return "", fmt.Errorf("unknown update channel %q (expected stable, beta, or dev)", s)
	}
}

// String returns the canonical channel string.
func (c Channel) String() string {
	if c == "" {
		return string(ChannelStable)
	}
	return string(c)
}

// AllowsPrerelease returns true if the channel accepts prerelease / RC builds.
func (c Channel) AllowsPrerelease() bool {
	return c == ChannelBeta || c == ChannelDev
}

// IsDev returns true if the channel is the development channel.
func (c Channel) IsDev() bool {
	return c == ChannelDev
}
