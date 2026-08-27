package signal

import (
	"net"
	"net/http"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of CIDR strings or bare IP
// addresses into a slice of *net.IPNet. Whitespace is trimmed and empty entries are ignored.
func ParseTrustedProxies(raw string) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	var nets []*net.IPNet
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			// Bare IP: convert to /32 (IPv4) or /128 (IPv6)
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, &net.ParseError{Type: "IP address", Text: p}
			}
			if ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// isTrustedProxy reports whether ip is covered by any network in trustedNets.
func isTrustedProxy(ip net.IP, trustedNets []*net.IPNet) bool {
	if ip == nil || len(trustedNets) == 0 {
		return false
	}
	for _, n := range trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP extracts the canonical client IP from an HTTP request.
//
// When trustedNets is empty or r.RemoteAddr is not from a trusted proxy,
// the direct remote address is returned verbatim and headers like X-Forwarded-For
// are deliberately ignored to prevent client spoofing.
//
// When r.RemoteAddr is in trustedNets, headers are parsed in priority order:
// 1. CF-Connecting-IP (Cloudflare)
// 2. X-Real-IP
// 3. X-Forwarded-For (evaluating right-to-left for the first untrusted upstream hop)
func ClientIP(r *http.Request, trustedNets []*net.IPNet) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remoteHost = strings.TrimSpace(remoteHost)
	if len(trustedNets) == 0 {
		return remoteHost
	}

	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !isTrustedProxy(remoteIP, trustedNets) {
		return remoteHost
	}

	// Remote peer is a trusted proxy. Check CF-Connecting-IP first.
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		if ip := net.ParseIP(cf); ip != nil {
			return ip.String()
		}
	}

	// Check X-Real-IP next.
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return ip.String()
		}
	}

	// Check X-Forwarded-For (comma-separated list of client, proxy1, proxy2...).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		// Walk backwards from rightmost (nearest proxy) to find the first untrusted IP.
		for i := len(hops) - 1; i >= 0; i-- {
			hop := strings.TrimSpace(hops[i])
			if hop == "" {
				continue
			}
			ip := net.ParseIP(hop)
			if ip == nil {
				continue
			}
			if !isTrustedProxy(ip, trustedNets) {
				return ip.String()
			}
		}
		// If all hops in XFF are trusted proxies, take the leftmost hop as the original client.
		for _, hop := range hops {
			hop = strings.TrimSpace(hop)
			if ip := net.ParseIP(hop); ip != nil {
				return ip.String()
			}
		}
	}

	return remoteHost
}
