// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package rtc

import (
	"net"
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestLocalOnlyNetsForIPs derives /32 and /128 nets from literals and skips
// nils. It never resolves names: DNS-rebinding defense starts here.
func TestLocalOnlyNetsForIPs(t *testing.T) {
	nets := LocalOnlyNetsForIPs([]net.IP{
		net.ParseIP("192.168.1.5"),
		net.ParseIP("fd00::1"),
		nil,
	})
	if len(nets) != 2 {
		t.Fatalf("got %d nets, want 2", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("192.168.1.5")) || nets[0].Contains(net.ParseIP("192.168.1.6")) {
		t.Fatalf("IPv4 net wrong: %v", nets[0])
	}
	if !nets[1].Contains(net.ParseIP("fd00::1")) || nets[1].Contains(net.ParseIP("fd00::2")) {
		t.Fatalf("IPv6 net wrong: %v", nets[1])
	}
}

// TestLocalOnlyAPIGathersOnlyApproved verifies the SettingEngine policy at
// the Pion level: with an allow-net that matches no local interface, no
// usable host candidate is gathered (fail-closed); loopback is always
// permitted.
func TestLocalOnlyAPIGathersOnlyApproved(t *testing.T) {
	// TEST-NET-1: guaranteed absent from any interface.
	_, testNet, _ := net.ParseCIDR("192.0.2.0/24")
	api := LocalOnlyAPI([]*net.IPNet{testNet})
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	if _, err := pc.CreateDataChannel("t", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	// Gather synchronously.
	gatherDone := webrtc.GatheringCompletePromise(pc)
	<-gatherDone

	sdp := pc.LocalDescription().SDP
	// No candidate line may carry a non-loopback, non-allow-net IP.
	// (Loopback is permitted by policy; TEST-NET-1 must not appear.)
	if containsIP(sdp, "192.0.2.") {
		t.Fatalf("gathered a candidate in the allow-net that has no interface:\n%s", sdp)
	}
}

// TestLocalOnlyAPILoopbackOnly: empty allow-nets still gather loopback.
func TestLocalOnlyAPILoopbackOnly(t *testing.T) {
	api := LocalOnlyAPI(nil)
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	if _, err := pc.CreateDataChannel("t", nil); err != nil {
		t.Fatal(err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-webrtc.GatheringCompletePromise(pc)

	sdp := pc.LocalDescription().SDP
	if !containsIP(sdp, "127.0.0.1") {
		t.Fatalf("expected a loopback host candidate with empty allow-nets:\n%s", sdp)
	}
}

func containsIP(sdp, ip string) bool {
	for _, line := range splitLines(sdp) {
		if len(line) > 11 && line[:11] == "a=candidate" && contains(line, ip) {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
