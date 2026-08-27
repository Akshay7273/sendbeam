package updater

import "testing"

func TestParseChannel(t *testing.T) {
	tests := []struct {
		input       string
		expected    Channel
		expectError bool
	}{
		{"stable", ChannelStable, false},
		{"STABLE", ChannelStable, false},
		{"", ChannelStable, false},
		{"beta", ChannelBeta, false},
		{"candidate", ChannelBeta, false},
		{"rc", ChannelBeta, false},
		{"dev", ChannelDev, false},
		{"nightly", "", true},
		{"invalid", "", true},
		{"alpha", "", true},
	}

	for _, tt := range tests {
		ch, err := ParseChannel(tt.input)
		if tt.expectError && err == nil {
			t.Errorf("ParseChannel(%q) expected error, got nil", tt.input)
		}
		if !tt.expectError && err != nil {
			t.Errorf("ParseChannel(%q) unexpected error: %v", tt.input, err)
		}
		if ch != tt.expected {
			t.Errorf("ParseChannel(%q) = %v, expected %v", tt.input, ch, tt.expected)
		}
	}
}

func TestChannelProperties(t *testing.T) {
	if ChannelStable.AllowsPrerelease() {
		t.Error("ChannelStable should not allow prerelease")
	}
	if !ChannelBeta.AllowsPrerelease() {
		t.Error("ChannelBeta should allow prerelease")
	}
	if !ChannelDev.AllowsPrerelease() {
		t.Error("ChannelDev should allow prerelease")
	}
}
