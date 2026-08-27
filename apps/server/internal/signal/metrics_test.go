package signal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsSnapshot(t *testing.T) {
	h := testHub(t)

	if m := h.Metrics(); m.Rooms != 0 || m.RelayBytes != 0 || len(m.Errors) != 0 {
		t.Fatalf("fresh hub metrics = %+v, want all zero", m)
	}

	a, b := newTestPeer(), newTestPeer()
	_, _ = h.createRoom(a, "127.0.0.1")
	room2, _ := h.createRoom(b, "127.0.0.1")
	joiner := newTestPeer()
	_, _ = h.join(joiner, room2, "127.0.0.1")

	h.recordError("bad_message")
	h.recordError("bad_message")
	h.recordError("room_full")
	h.recordMessage("create")
	h.recordMessage("join")

	m := h.Metrics()
	if m.Rooms != 2 {
		t.Errorf("Rooms = %d, want 2", m.Rooms)
	}
	if m.RoomsCreatedTotal != 2 {
		t.Errorf("RoomsCreatedTotal = %d, want 2", m.RoomsCreatedTotal)
	}
	if m.RoomsPairedTotal != 1 {
		t.Errorf("RoomsPairedTotal = %d, want 1", m.RoomsPairedTotal)
	}
	if m.Errors["bad_message"] != 2 || m.Errors["room_full"] != 1 {
		t.Errorf("Errors = %v, want bad_message=2 room_full=1", m.Errors)
	}
	if m.Messages["create"] != 1 || m.Messages["join"] != 1 {
		t.Errorf("Messages = %v, want create=1 join=1", m.Messages)
	}
}

func TestMetricsHandlerRendersPrometheusText(t *testing.T) {
	h := testHub(t)
	h.recordError("room_full")
	h.recordMessage("pake")

	rec := httptest.NewRecorder()
	h.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if got := rec.Code; got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE sendbeam_rooms gauge",
		"sendbeam_rooms 0",
		"# TYPE sendbeam_active_connections gauge",
		"sendbeam_active_connections 0",
		"# TYPE sendbeam_connections_total counter",
		"sendbeam_connections_total 0",
		"# TYPE sendbeam_rooms_created_total counter",
		"sendbeam_rooms_created_total 0",
		"# TYPE sendbeam_rooms_paired_total counter",
		"sendbeam_rooms_paired_total 0",
		"# TYPE sendbeam_rooms_reaped_total counter",
		"sendbeam_rooms_reaped_total 0",
		"# TYPE sendbeam_relay_bytes_total counter",
		"sendbeam_relay_bytes_total 0",
		`sendbeam_errors_total{code="room_full"} 1`,
		`sendbeam_messages_total{type="pake"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}

	// Verify no high cardinality or PII strings appear in metrics
	for _, forbidden := range []string{"127.0.0.1", "ip", "client", "room_0", "token"} {
		if strings.Contains(body, forbidden+"=") {
			t.Errorf("metrics must not contain PII or high-cardinality labels: %s", forbidden)
		}
	}
}
