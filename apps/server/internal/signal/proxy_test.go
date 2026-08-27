package signal

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{name: "empty", input: "", wantLen: 0, wantErr: false},
		{name: "single cidr", input: "127.0.0.1/32", wantLen: 1, wantErr: false},
		{name: "bare ip", input: "127.0.0.1", wantLen: 1, wantErr: false},
		{name: "ipv6 bare", input: "::1", wantLen: 1, wantErr: false},
		{name: "multiple mixed", input: "10.0.0.0/8, 172.16.0.0/12, 192.168.1.1, ::1/128", wantLen: 4, wantErr: false},
		{name: "invalid cidr", input: "999.999.999.999/32", wantLen: 0, wantErr: true},
		{name: "invalid ip", input: "not-an-ip", wantLen: 0, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := ParseTrustedProxies(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTrustedProxies(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if len(nets) != tt.wantLen {
				t.Fatalf("ParseTrustedProxies(%q) got len %d, want %d", tt.input, len(nets), tt.wantLen)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.1/32, 10.0.0.0/8, 192.168.0.0/16, ::1/128")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		trusted    bool
		wantIP     string
	}{
		{
			name:       "direct untrusted ignores xff",
			remoteAddr: "203.0.113.50:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1"},
			trusted:    true,
			wantIP:     "203.0.113.50",
		},
		{
			name:       "direct untrusted ignores cf-connecting-ip",
			remoteAddr: "203.0.113.50:54321",
			headers:    map[string]string{"CF-Connecting-IP": "198.51.100.1"},
			trusted:    true,
			wantIP:     "203.0.113.50",
		},
		{
			name:       "no trusted proxies configured ignores headers",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1"},
			trusted:    false,
			wantIP:     "127.0.0.1",
		},
		{
			name:       "trusted proxy with single xff",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.77"},
			trusted:    true,
			wantIP:     "203.0.113.77",
		},
		{
			name:       "trusted proxy with chained xff picks rightmost untrusted",
			remoteAddr: "10.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.22, 203.0.113.99, 10.0.0.2"},
			trusted:    true,
			wantIP:     "203.0.113.99",
		},
		{
			name:       "trusted proxy with cf-connecting-ip takes precedence",
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.123",
				"X-Forwarded-For":  "198.51.100.22",
			},
			trusted: true,
			wantIP:  "203.0.113.123",
		},
		{
			name:       "trusted proxy with x-real-ip fallback",
			remoteAddr: "192.168.1.1:54321",
			headers:    map[string]string{"X-Real-IP": "203.0.113.88"},
			trusted:    true,
			wantIP:     "203.0.113.88",
		},
		{
			name:       "trusted proxy with all trusted hops in xff returns leftmost",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.5, 10.0.0.2"},
			trusted:    true,
			wantIP:     "10.0.0.5",
		},
		{
			name:       "trusted proxy ipv6",
			remoteAddr: "[::1]:54321",
			headers:    map[string]string{"X-Forwarded-For": "2001:db8::1"},
			trusted:    true,
			wantIP:     "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/ws", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			var nets []*net.IPNet
			if tt.trusted {
				nets = trusted
			}
			got := ClientIP(r, nets)
			if got != tt.wantIP {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}
