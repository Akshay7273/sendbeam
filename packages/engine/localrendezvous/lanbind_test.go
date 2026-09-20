// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localrendezvous

import (
	"net"
	"strings"
	"testing"
)

func TestLANBindAddrShape(t *testing.T) {
	addr, err := LANBindAddr()
	if err != nil {
		t.Skipf("no LAN interface in this environment: %v", err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	if port != "0" {
		t.Fatalf("port = %q, want 0 (ephemeral)", port)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("host %q is not an IPv4 literal", host)
	}
	if ip.IsLoopback() {
		t.Fatalf("host %q is loopback: a pairing invitation carrying it is unreachable from other devices", host)
	}
	if strings.Contains(addr, "[") {
		t.Fatalf("addr %q must not be bracketed IPv6", addr)
	}
}
