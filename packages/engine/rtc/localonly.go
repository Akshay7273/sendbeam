// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package rtc

import (
	"net"
	"time"

	"github.com/pion/webrtc/v4"
)

// LocalOnlyAPI builds a *webrtc.API whose SettingEngine enforces the v2.1
// local-only ICE candidate policy (ADR 0011):
//
//   - Local gathering is restricted to host candidates whose IP falls within
//     allowedNets. Loopback candidates are always included so same-machine
//     pairing (and loopback test routes) work.
//   - Remote candidates whose IP falls outside allowedNets are rejected by
//     the ICE agent before use. There is no fallback: an outside-policy
//     candidate is ignored, and if no approved route remains ICE fails
//     closed.
//   - The caller still passes explicit empty ICE servers (no STUN/TURN);
//     this API additionally pins gathering to the approved networks so a
//     host candidate can never escape the selected local route.
//
// An empty allowedNets permits loopback only. Each entry is typically a
// /32 (IPv4) or /128 (IPv6) derived from the validated route candidate's
// pinned IPs (PR03); broader prefixes are honored as given.
func LocalOnlyAPI(allowedNets []*net.IPNet) *webrtc.API {
	keep := func(ip net.IP) bool {
		if ip.IsLoopback() {
			return true
		}
		for _, n := range allowedNets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}

	s := webrtc.SettingEngine{}
	// Bound the failed state so a policy with no usable route fails fast
	// instead of hanging on Pion's long defaults (mirrors NewPeer).
	s.SetICETimeouts(3*time.Second, 8*time.Second, 2*time.Second)
	s.SetIncludeLoopbackCandidate(true)
	s.SetIPFilter(keep)
	s.SetRemoteIPFilter(keep)
	return webrtc.NewAPI(webrtc.WithSettingEngine(s))
}

// LocalOnlyNetsForIPs derives /32 (IPv4) or /128 (IPv6) allow-nets from a
// validated endpoint's pinned IPs. It never re-resolves names: IPs must
// already be literals (PR03 pinned endpoints).
func LocalOnlyNetsForIPs(ips []net.IP) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			nets = append(nets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else if ip16 := ip.To16(); ip16 != nil {
			nets = append(nets, &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)})
		}
	}
	return nets
}
