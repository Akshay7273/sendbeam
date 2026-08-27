package signal

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Metrics is a point-in-time snapshot of server-wide counters, rendered by
// /metrics in the Prometheus text format. Nothing here reveals content or PII:
// rooms count live sessions, active connections count sockets, relayBytes counts
// ciphertext, errors and messages count counts by opaque code/type.
type Metrics struct {
	Rooms             int
	ActiveConnections int
	ConnectionsTotal  int64
	RoomsCreatedTotal int64
	RoomsPairedTotal  int64
	RoomsReapedTotal  int64
	RelayBytes        int64
	Errors            map[string]int64
	Messages          map[string]int64
}

// Metrics returns a snapshot of the hub's counters. All fields are guarded by
// hub.mu, which also protects room state, connection tracking, and relay byte accounting.
func (h *Hub) Metrics() Metrics {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := Metrics{
		Rooms:             len(h.rooms),
		ActiveConnections: h.activeConns,
		ConnectionsTotal:  h.connsTotal,
		RoomsCreatedTotal: h.roomsCreatedTotal,
		RoomsPairedTotal:  h.roomsPairedTotal,
		RoomsReapedTotal:  h.roomsReapedTotal,
		RelayBytes:        h.relayBytes,
		Errors:            make(map[string]int64, len(h.errors)),
		Messages:          make(map[string]int64, len(h.messages)),
	}
	for code, n := range h.errors {
		m.Errors[code] = n
	}
	for typ, n := range h.messages {
		m.Messages[typ] = n
	}
	return m
}

// recordError counts one refusal or protocol error by code.
func (h *Hub) recordError(code string) {
	if code == "" {
		return
	}
	h.mu.Lock()
	h.errors[code]++
	h.mu.Unlock()
}

// recordMessage counts one parsed client message by type.
func (h *Hub) recordMessage(typ string) {
	if typ == "" {
		return
	}
	h.mu.Lock()
	h.messages[typ]++
	h.mu.Unlock()
}

// MetricsHandler serves Prometheus text metrics.
func (h *Hub) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m := h.Metrics()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder

		b.WriteString("# HELP sendbeam_rooms Active signaling rooms (live sessions).\n")
		b.WriteString("# TYPE sendbeam_rooms gauge\n")
		fmt.Fprintf(&b, "sendbeam_rooms %d\n", m.Rooms)

		b.WriteString("# HELP sendbeam_active_connections Active WebSocket connections.\n")
		b.WriteString("# TYPE sendbeam_active_connections gauge\n")
		fmt.Fprintf(&b, "sendbeam_active_connections %d\n", m.ActiveConnections)

		b.WriteString("# HELP sendbeam_connections_total Total WebSocket connections accepted since start.\n")
		b.WriteString("# TYPE sendbeam_connections_total counter\n")
		fmt.Fprintf(&b, "sendbeam_connections_total %d\n", m.ConnectionsTotal)

		b.WriteString("# HELP sendbeam_rooms_created_total Total rooms created since start.\n")
		b.WriteString("# TYPE sendbeam_rooms_created_total counter\n")
		fmt.Fprintf(&b, "sendbeam_rooms_created_total %d\n", m.RoomsCreatedTotal)

		b.WriteString("# HELP sendbeam_rooms_paired_total Total rooms paired since start.\n")
		b.WriteString("# TYPE sendbeam_rooms_paired_total counter\n")
		fmt.Fprintf(&b, "sendbeam_rooms_paired_total %d\n", m.RoomsPairedTotal)

		b.WriteString("# HELP sendbeam_rooms_reaped_total Total idle rooms reaped since start.\n")
		b.WriteString("# TYPE sendbeam_rooms_reaped_total counter\n")
		fmt.Fprintf(&b, "sendbeam_rooms_reaped_total %d\n", m.RoomsReapedTotal)

		b.WriteString("# HELP sendbeam_relay_bytes_total Ciphertext bytes relayed since server start.\n")
		b.WriteString("# TYPE sendbeam_relay_bytes_total counter\n")
		fmt.Fprintf(&b, "sendbeam_relay_bytes_total %d\n", m.RelayBytes)

		b.WriteString("# HELP sendbeam_errors_total Error frames and refusals sent, by refusal code.\n")
		b.WriteString("# TYPE sendbeam_errors_total counter\n")
		codes := make([]string, 0, len(m.Errors))
		for code := range m.Errors {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		for _, code := range codes {
			fmt.Fprintf(&b, "sendbeam_errors_total{code=%q} %d\n", code, m.Errors[code])
		}

		b.WriteString("# HELP sendbeam_messages_total Inbound signaling and control messages by type.\n")
		b.WriteString("# TYPE sendbeam_messages_total counter\n")
		types := make([]string, 0, len(m.Messages))
		for typ := range m.Messages {
			types = append(types, typ)
		}
		sort.Strings(types)
		for _, typ := range types {
			fmt.Fprintf(&b, "sendbeam_messages_total{type=%q} %d\n", typ, m.Messages[typ])
		}

		_, _ = w.Write([]byte(b.String()))
	})
}
