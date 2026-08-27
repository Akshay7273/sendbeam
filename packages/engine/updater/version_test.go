package updater

import (
	"testing"
)

func TestVersionParsingAndComparison(t *testing.T) {
	tests := []struct {
		name        string
		v1          string
		v2          string
		v1GreaterV2 bool
		equal       bool
	}{
		{
			name:        "equal basic",
			v1:          "1.4.0",
			v2:          "1.4.0",
			v1GreaterV2: false,
			equal:       true,
		},
		{
			name:        "equal with v prefix",
			v1:          "v1.4.0",
			v2:          "1.4.0",
			v1GreaterV2: false,
			equal:       true,
		},
		{
			name:        "patch upgrade",
			v1:          "1.4.1",
			v2:          "1.4.0",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "minor upgrade",
			v1:          "1.5.0",
			v2:          "1.4.99",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "major upgrade",
			v1:          "2.0.0",
			v2:          "1.99.99",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "stable vs beta",
			v1:          "1.5.0",
			v2:          "1.5.0-beta.1",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "beta1 vs beta2",
			v1:          "1.5.0-beta.2",
			v2:          "1.5.0-beta.1",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "beta vs rc",
			v1:          "1.5.0-rc.1",
			v2:          "1.5.0-beta.2",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "rc vs release",
			v1:          "1.5.0",
			v2:          "1.5.0-rc.1",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "dev vs release",
			v1:          "dev",
			v2:          "1.4.0",
			v1GreaterV2: false,
			equal:       false,
		},
		{
			name:        "release vs dev",
			v1:          "1.4.0",
			v2:          "dev",
			v1GreaterV2: true,
			equal:       false,
		},
		{
			name:        "dev vs dev",
			v1:          "dev",
			v2:          "dev",
			v1GreaterV2: false,
			equal:       true,
		},
		{
			name:        "ignore build metadata",
			v1:          "1.4.0+sha.123",
			v2:          "1.4.0+sha.456",
			v1GreaterV2: false,
			equal:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver1, err := ParseVersion(tt.v1)
			if err != nil {
				t.Fatalf("ParseVersion(%q) failed: %v", tt.v1, err)
			}
			ver2, err := ParseVersion(tt.v2)
			if err != nil {
				t.Fatalf("ParseVersion(%q) failed: %v", tt.v2, err)
			}

			if got := ver1.IsGreaterThan(ver2); got != tt.v1GreaterV2 {
				t.Errorf("%q > %q = %v, expected %v", tt.v1, tt.v2, got, tt.v1GreaterV2)
			}

			if tt.equal && (ver1.IsGreaterThan(ver2) || ver2.IsGreaterThan(ver1)) {
				t.Errorf("%q and %q should be equal", tt.v1, tt.v2)
			}
		})
	}
}

func TestVersionChannelCompatibility(t *testing.T) {
	stableVer, _ := ParseVersion("1.4.0")
	betaVer, _ := ParseVersion("1.5.0-beta.1")
	rcVer, _ := ParseVersion("1.5.0-rc.1")
	devVer, _ := ParseVersion("dev")

	// Stable channel: allows stable only
	if !stableVer.CompatibleWithChannel(ChannelStable) {
		t.Error("stable version should be compatible with ChannelStable")
	}
	if betaVer.CompatibleWithChannel(ChannelStable) {
		t.Error("beta version should NOT be compatible with ChannelStable")
	}
	if rcVer.CompatibleWithChannel(ChannelStable) {
		t.Error("rc version should NOT be compatible with ChannelStable")
	}
	if devVer.CompatibleWithChannel(ChannelStable) {
		t.Error("dev version should NOT be compatible with ChannelStable")
	}

	// Beta channel: allows stable + beta + rc
	if !stableVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("stable version should be compatible with ChannelBeta")
	}
	if !betaVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("beta version should be compatible with ChannelBeta")
	}
	if !rcVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("rc version should be compatible with ChannelBeta")
	}
	if devVer.CompatibleWithChannel(ChannelBeta) {
		t.Error("dev version should NOT be compatible with ChannelBeta")
	}

	// Dev channel: allows dev builds
	if !devVer.CompatibleWithChannel(ChannelDev) {
		t.Error("dev version should be compatible with ChannelDev")
	}
}
