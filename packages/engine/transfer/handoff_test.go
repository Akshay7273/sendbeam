package transfer

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// V20-PR06 failing regression: explicit encrypted text/link handoffs through
// the existing transfer and consent paths.

// --- NewTextSource validation -------------------------------------------------

func TestNewTextSourceValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    string
		text    string
		wantErr string
	}{
		{"text ok", wire.ContentKindText, "hello", ""},
		{"link ok", wire.ContentKindLink, "https://example.com/x?y=1", ""},
		{"http link ok", wire.ContentKindLink, "http://example.com", ""},
		{"unknown kind", "audio", "hello", "unknown content kind"},
		{"empty text", wire.ContentKindText, "", "empty"},
		{"oversize text", wire.ContentKindText, strings.Repeat("a", wire.MaxHandoffBytes+1), "ceiling"},
		{"invalid utf8", wire.ContentKindText, string([]byte{0xff, 0xfe}), "UTF-8"},
		{"ftp link rejected", wire.ContentKindLink, "ftp://example.com/x", "http(s)"},
		{"bare host rejected", wire.ContentKindLink, "example.com", "http(s)"},
		{"javascript scheme rejected", wire.ContentKindLink, "javascript:alert(1)", "http(s)"},
		{"empty link", wire.ContentKindLink, "", "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := NewTextSource(tc.kind, tc.text)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected ok, got %v", err)
				}
				if meta := src.Meta(); meta.Size != int64(len(tc.text)) {
					t.Fatalf("size = %d, want %d", meta.Size, len(tc.text))
				}
				if !strings.HasPrefix(src.Meta().Mime, "text/plain") {
					t.Fatalf("mime = %q, want text/plain", src.Meta().Mime)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got ok", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewTextSourceCapBoundary(t *testing.T) {
	exact := strings.Repeat("b", wire.MaxHandoffBytes)
	src, err := NewTextSource(wire.ContentKindText, exact)
	if err != nil {
		t.Fatalf("cap-sized text rejected: %v", err)
	}
	if src.Meta().Size != wire.MaxHandoffBytes {
		t.Fatalf("size = %d, want %d", src.Meta().Size, wire.MaxHandoffBytes)
	}
}

// --- HandoffDestination --------------------------------------------------------

func handoffManifestForTest(t *testing.T, kind string, size int64) wire.Manifest {
	t.Helper()
	m := wire.NewManifest([]wire.FileEntry{{
		Idx: 0, Name: HandoffFileName(kind), Size: size, Mime: "text/plain; charset=utf-8",
		LastModified: 1, BlockSize: int(size), Blocks: 1, FileDigest: "ab",
	}}, size)
	m.ContentKind = kind
	validated, err := wire.ValidateManifest(*m)
	if err != nil {
		t.Fatalf("fixture manifest invalid: %v", err)
	}
	return validated
}

func TestHandoffDestinationRejectsNonEnvelope(t *testing.T) {
	d := NewHandoffDestination(wire.ContentKindText)
	plain := wire.NewManifest([]wire.FileEntry{{
		Idx: 0, Name: "a.bin", Size: 4, Mime: "application/octet-stream",
		LastModified: 1, BlockSize: 4, Blocks: 1, FileDigest: "ab",
	}}, 4)
	validated, err := wire.ValidateManifest(*plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Prepare(validated); err == nil {
		t.Fatal("Prepare accepted a non-handoff manifest")
	}
}

func TestHandoffDestinationCaptureRoundTrip(t *testing.T) {
	const payload = "Buy milk — and call Amma."
	d := NewHandoffDestination(wire.ContentKindText)
	m := handoffManifestForTest(t, wire.ContentKindText, int64(len(payload)))
	if err := d.Prepare(m); err != nil {
		t.Fatal(err)
	}
	sink, err := d.Open(m.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Open(m.Files[0]); err == nil {
		t.Fatal("second Open accepted")
	}
	half := len(payload) / 2
	if err := sink.Write(0, []byte(payload[:half])); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(int64(half), []byte(payload[half:])); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(int64(len(payload)), []byte("x")); err == nil {
		t.Fatal("over-cap write accepted")
	}
	if _, _, err := d.Content(); err == nil {
		t.Fatal("Content available before verified completion")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	kind, text, err := d.Content()
	if err != nil {
		t.Fatal(err)
	}
	if kind != wire.ContentKindText || text != payload {
		t.Fatalf("content = (%q, %q), want (%q, %q)", kind, text, wire.ContentKindText, payload)
	}
}

func TestHandoffDestinationAbortDiscards(t *testing.T) {
	d := NewHandoffDestination(wire.ContentKindText)
	m := handoffManifestForTest(t, wire.ContentKindText, 5)
	if err := d.Prepare(m); err != nil {
		t.Fatal(err)
	}
	sink, err := d.Open(m.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := d.Abort("declined"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Content(); err == nil {
		t.Fatal("Content available after abort")
	}
}

func TestHandoffDestinationOutOfOrderRejected(t *testing.T) {
	d := NewHandoffDestination(wire.ContentKindText)
	m := handoffManifestForTest(t, wire.ContentKindText, 5)
	if err := d.Prepare(m); err != nil {
		t.Fatal(err)
	}
	sink, err := d.Open(m.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(2, []byte("llo")); err == nil {
		t.Fatal("out-of-order write accepted")
	}
}

// --- End-to-end: encrypted text handoff through the production driver ----------

func TestDriverLoopbackTextHandoff(t *testing.T) {
	hub := newRelay()
	dir := t.TempDir()

	const payload = "Encrypted handoff — no clipboard, no auto-open."

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)

	var consentKind string
	go func() {
		src, err := NewTextSource(wire.ContentKindText, payload)
		if err != nil {
			sendDone <- result{nil, err}
			return
		}
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      src,
			ContentKind: wire.ContentKindText,
			ICEServers:  []webrtc.ICEServer{},
		})
		sendDone <- result{out, err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
			Consent: func(cctx context.Context, req ConsentRequest) (ConsentDecision, error) {
				consentKind = req.ContentKind
				return ConsentDecision{Accepted: true}, nil
			},
		})
		recvDone <- result{out, err}
	}()

	send := <-sendDone
	recv := <-recvDone
	if send.err != nil {
		t.Fatalf("sender: %v", send.err)
	}
	if recv.err != nil {
		t.Fatalf("receiver: %v", recv.err)
	}

	// The consent path carried the handoff kind.
	if consentKind != wire.ContentKindText {
		t.Fatalf("consent kind = %q, want %q", consentKind, wire.ContentKindText)
	}
	// The verified payload is exposed for deliberate receiver actions.
	if recv.out.ContentKind != wire.ContentKindText {
		t.Fatalf("outcome kind = %q, want %q", recv.out.ContentKind, wire.ContentKindText)
	}
	if recv.out.Content != payload {
		t.Fatalf("outcome content = %q, want %q", recv.out.Content, payload)
	}
	// Nothing was written to the destination directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("destination dir has %d entries; handoff must not write files", len(entries))
	}
	if recv.out.Path != "" {
		t.Fatalf("outcome path = %q, want empty for a handoff", recv.out.Path)
	}
	// Digests still agree across peers: the handoff was fully verified.
	if send.out.Digest != recv.out.Digest {
		t.Errorf("digests differ: sender %s, receiver %s", send.out.Digest, recv.out.Digest)
	}
}

func TestDriverLoopbackLinkHandoff(t *testing.T) {
	hub := newRelay()
	dir := t.TempDir()

	const payload = "https://example.com/meeting-notes?room=7"

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)

	go func() {
		src, err := NewTextSource(wire.ContentKindLink, payload)
		if err != nil {
			sendDone <- result{nil, err}
			return
		}
		out, err := Run(ctx, hub.off, Spec{
			Session:     rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:      src,
			ContentKind: wire.ContentKindLink,
			ICEServers:  []webrtc.ICEServer{},
		})
		sendDone <- result{out, err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
			Consent: func(cctx context.Context, req ConsentRequest) (ConsentDecision, error) {
				if req.ContentKind != wire.ContentKindLink {
					t.Errorf("consent kind = %q, want link", req.ContentKind)
				}
				return ConsentDecision{Accepted: true}, nil
			},
		})
		recvDone <- result{out, err}
	}()

	send := <-sendDone
	recv := <-recvDone
	if send.err != nil {
		t.Fatalf("sender: %v", send.err)
	}
	if recv.err != nil {
		t.Fatalf("receiver: %v", recv.err)
	}
	if recv.out.ContentKind != wire.ContentKindLink || recv.out.Content != payload {
		t.Fatalf("outcome = (%q, %q), want (link, %q)", recv.out.ContentKind, recv.out.Content, payload)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("destination dir has %d entries; handoff must not write files", len(entries))
	}
}

// V20-PR06: ValidateHandoffPayload is the shared envelope invariant for both
// sides of the wire. The receiver re-runs it in Close after the digest
// verified: a sender that marks malformed bytes as text/link fails the
// receive instead of handing the UI something to second-guess.
func TestValidateHandoffPayload(t *testing.T) {
	for _, tc := range []struct {
		name, kind, text string
	}{
		{"text", wire.ContentKindText, "hello"},
		{"link", wire.ContentKindLink, "https://example.com/x"},
	} {
		if err := ValidateHandoffPayload(tc.kind, tc.text); err != nil {
			t.Fatalf("%s: valid payload rejected: %v", tc.name, err)
		}
	}
	for _, tc := range []struct {
		kind, text string
	}{
		{"audio", "hello"},                    // unknown kind
		{wire.ContentKindText, ""},            // empty
		{wire.ContentKindText, "bad\xffutf8"}, // invalid UTF-8
		{wire.ContentKindText, strings.Repeat("a", wire.MaxHandoffBytes+1)}, // oversize
		{wire.ContentKindLink, "javascript:alert(1)"},                       // bad scheme
		{wire.ContentKindLink, "ftp://example.com/x"},                       // unsupported scheme
		{wire.ContentKindLink, "https://exam ple.com"},                      // whitespace
		{wire.ContentKindLink, "https://"},                                  // no host
		{wire.ContentKindLink, "not a url at all"},                          // garbage
	} {
		if err := ValidateHandoffPayload(tc.kind, tc.text); err == nil {
			t.Fatalf("accepted invalid payload kind=%q text=%q", tc.kind, tc.text)
		}
	}
}

// V20-PR06: a handoff destination whose verified bytes violate the typed
// envelope fails Close — the transfer errors instead of delivering garbage.
func TestHandoffDestinationCloseRejectsMalformedPayload(t *testing.T) {
	mk := func(kind, body string) *HandoffDestination {
		d := NewHandoffDestination(kind)
		m := wire.Manifest{
			TransferID:  "x",
			ContentKind: kind,
			Files:       []wire.FileEntry{{Idx: 0, Name: "text.txt", Size: int64(len(body)), Mime: "text/plain"}},
			TotalSize:   int64(len(body)),
		}
		if err := d.Prepare(m); err != nil {
			t.Fatal(err)
		}
		sink, err := d.Open(m.Files[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Write(0, []byte(body)); err != nil {
			t.Fatal(err)
		}
		return d
	}

	// A link envelope carrying a javascript: URL must fail closed.
	bad := mk(wire.ContentKindLink, "javascript:alert(1)")
	if err := bad.Close(); err == nil {
		t.Fatal("Close accepted a javascript: link handoff")
	}
	if _, _, err := bad.Content(); err == nil {
		t.Fatal("Content available after failed Close")
	}

	// A valid payload still completes.
	good := mk(wire.ContentKindText, "hello")
	if err := good.Close(); err != nil {
		t.Fatalf("Close rejected a valid handoff: %v", err)
	}
	kind, text, err := good.Content()
	if err != nil || kind != wire.ContentKindText || text != "hello" {
		t.Fatalf("Content = %q %q, %v", kind, text, err)
	}
}

// TestOpaqueSessionCapsHandoffNegotiated proves a capable opaque peer is
// credited with the handoff capability: when both sides advertise it, the
// authenticated intersection carries it and the remote view has it.
func TestOpaqueSessionCapsHandoffNegotiated(t *testing.T) {
	negotiated := []string{"sendbeam/3", "transfer.v1", "padding", "folders", "relay", wire.HandoffCapability}
	local, remote := opaqueSessionCaps(negotiated)
	if !containsString(local.Features, wire.HandoffCapability) {
		t.Fatal("local caps must always advertise handoff support")
	}
	if !containsString(remote.Features, wire.HandoffCapability) {
		t.Fatal("remote caps must carry negotiated handoff support")
	}
}

// TestOpaqueSessionCapsOldPeerRefused proves the downgrade guard: an older
// opaque peer that never advertised "handoff" is NOT credited with it, so the
// sender's fail-closed check (driver send) fires before any manifest is
// transmitted instead of downgrading the handoff into a saved text.txt.
func TestOpaqueSessionCapsOldPeerRefused(t *testing.T) {
	// The intersection the trusted-auth handshake would produce with an old
	// peer: everything both sides advertised, minus "handoff".
	negotiated := []string{"sendbeam/3", "transfer.v1", "padding", "folders", "relay"}
	local, remote := opaqueSessionCaps(negotiated)
	if !containsString(local.Features, wire.HandoffCapability) {
		t.Fatal("local caps must always advertise handoff support")
	}
	if containsString(remote.Features, wire.HandoffCapability) {
		t.Fatal("remote caps must not invent handoff support the peer never advertised")
	}
	// Mirror the driver's send gate: a handoff spec against these remote caps
	// must be refused.
	spec := Spec{ContentKind: wire.ContentKindText}
	refused := spec.ContentKind != "" && !containsString(remote.Features, wire.HandoffCapability)
	if !refused {
		t.Fatal("handoff send to an old opaque peer must be refused")
	}
}

// TestOpaqueSessionCapsOrdinaryTransferCompatible proves ordinary file
// transfers are unaffected: with no handoff involved the send gate never
// fires regardless of the peer's vintage.
func TestOpaqueSessionCapsOrdinaryTransferCompatible(t *testing.T) {
	for _, negotiated := range [][]string{
		{"sendbeam/3", "transfer.v1", "padding", "folders", "relay", wire.HandoffCapability},
		{"sendbeam/3", "transfer.v1", "padding", "folders", "relay"},
	} {
		_, remote := opaqueSessionCaps(negotiated)
		spec := Spec{} // ordinary file send: no ContentKind
		refused := spec.ContentKind != "" && !containsString(remote.Features, wire.HandoffCapability)
		if refused {
			t.Fatalf("ordinary send refused for negotiated caps %v", negotiated)
		}
	}
}

// TestDefaultCapsAdvertiseHandoff pins the contract the opaque conversion
// relies on: this peer's defaults advertise the handoff capability.
func TestDefaultCapsAdvertiseHandoff(t *testing.T) {
	if !containsString(rendezvous.DefaultCaps().Features, wire.HandoffCapability) {
		t.Fatal("DefaultCaps must advertise the handoff capability")
	}
}

// TestHandoffSuppressesTransferID proves the ephemeral contract: a handoff
// send mints no transfer id and advertises none, so there is nothing for a
// resume handshake, a sender record, or a receiver journal to bind to.
func TestHandoffSuppressesTransferID(t *testing.T) {
	for _, kind := range []string{wire.ContentKindText, wire.ContentKindLink} {
		spec := Spec{ContentKind: kind, TransferID: "should-not-leak"}
		if got := handoffTransferID(spec); got != "" {
			t.Fatalf("kind %q: advertised transfer id %q, want empty", kind, got)
		}
		if fn := handoffNewTransferID(spec); fn != nil {
			t.Fatalf("kind %q: id mint not suppressed", kind)
		}
	}
}

// TestOrdinarySendKeepsTransferID proves the suppression is handoff-only: an
// ordinary file send still carries its stable id for resumption.
func TestOrdinarySendKeepsTransferID(t *testing.T) {
	spec := Spec{TransferID: "stable-id"}
	if got := handoffTransferID(spec); got != "stable-id" {
		t.Fatalf("advertised transfer id %q, want %q", got, "stable-id")
	}
	if fn := handoffNewTransferID(spec); fn == nil {
		t.Fatal("id mint suppressed for an ordinary send")
	}
}
