package signal

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzParseTrustedProxies exercises the CIDR and bare IP parser for trusted reverse proxies.
// Invariants:
// 1. ParseTrustedProxies must never panic on any input string.
// 2. If ParseTrustedProxies succeeds, every returned *net.IPNet must be non-nil.
// 3. isTrustedProxy must evaluate safely without panicking.
func FuzzParseTrustedProxies(f *testing.F) {
	seeds := []string{
		"",
		"127.0.0.1/32",
		"127.0.0.1",
		"::1",
		"::1/128",
		"10.0.0.0/8, 172.16.0.0/12, 192.168.1.1, ::1/128",
		"invalid",
		"999.999.999.999/32",
		"10.0.0.1/999",
		",,,,,",
		"   10.0.0.1   ,   192.168.1.1/24   ",
		"\x00\x00\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		nets, err := ParseTrustedProxies(raw)
		if err != nil {
			return
		}

		for _, n := range nets {
			if n == nil {
				t.Fatalf("ParseTrustedProxies returned nil IPNet entry")
			}
			_ = isTrustedProxy(n.IP, nets)
		}
	})
}

// FuzzClientIP exercises remote IP resolution and reverse-proxy header traversal.
// Invariants:
// 1. ClientIP must never panic regardless of header shapes, malformed IPs, or spoof attempts.
// 2. ClientIP must return a non-empty string when RemoteAddr is provided with non-whitespace content.
func FuzzClientIP(f *testing.F) {
	trustedNets, _ := ParseTrustedProxies("127.0.0.1/32, 10.0.0.0/8, 192.168.0.0/16, ::1/128")

	f.Add("127.0.0.1:12345", "198.51.100.1", "198.51.100.2", "198.51.100.3")
	f.Add("203.0.113.50:54321", "10.0.0.1, 198.51.100.1", "", "")
	f.Add("[::1]:8080", "", "2001:db8::1", "")
	f.Add("invalid-remote", "bad, ips, here", "also-bad", "not-an-ip")
	f.Add(":", "", "", "")
	f.Add(":8080", "", "", "")
	f.Add(" ", "", "", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, remoteAddr, xff, xRealIP, cfIP string) {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/ws", nil)
		req.RemoteAddr = remoteAddr

		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		if xRealIP != "" {
			req.Header.Set("X-Real-IP", xRealIP)
		}
		if cfIP != "" {
			req.Header.Set("CF-Connecting-IP", cfIP)
		}

		// Determine expected presence of client IP:
		// ClientIP extracts the host portion via SplitHostPort (or trimmed RemoteAddr if no port).
		// If the resulting host string is non-empty, ClientIP must return a non-empty IP.
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			host = remoteAddr
		}
		host = strings.TrimSpace(host)

		// Test with trusted networks configured
		ip1 := ClientIP(req, trustedNets)
		if host != "" && ip1 == "" {
			t.Fatalf("ClientIP returned empty string for non-empty host %q (RemoteAddr: %q)", host, remoteAddr)
		}

		// Test with untrusted/empty networks
		ip2 := ClientIP(req, nil)
		if host != "" && ip2 == "" {
			t.Fatalf("ClientIP returned empty string with nil trusted nets for host %q (RemoteAddr: %q)", host, remoteAddr)
		}
	})
}
