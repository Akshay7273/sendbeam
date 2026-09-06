package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/wsclient"
	"github.com/sendbeam/wire"
)

func TestExecuteSend_MissingFileArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := executeSend([]string{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing file, got %d", code)
	}
	if !strings.Contains(stderr.String(), "a file to send is required") {
		t.Fatalf("expected error message in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_TargetDeviceResolutionError(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		testFile,
		"@nonexistent",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for unresolvable device, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not found in trust store") {
		t.Fatalf("expected 'not found in trust store' in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_RevokedDeviceRejection(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	devID := wire.DeriveDeviceID(pub)
	now := time.Now().UTC()

	ctx := context.Background()
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          devID,
		PublicKey:         hex.EncodeToString(pub),
		LocalLabel:        "OldLaptop",
		PairCredentialRef: "cred-1",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Revoked:           true,
		Policy:            wire.DefaultTrustPolicy(),
	})

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		testFile,
		"@OldLaptop",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for revoked device, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "is revoked") {
		t.Fatalf("expected 'is revoked' in stderr, got: %s", stderr.String())
	}
}

func TestExecuteSend_MultipleTargetArgParsing(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	dev1 := wire.DeriveDeviceID(pub1)
	dev2 := wire.DeriveDeviceID(pub2)
	now := time.Now().UTC()

	ctx := context.Background()
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          dev1,
		PublicKey:         hex.EncodeToString(pub1),
		LocalLabel:        "laptop",
		PairCredentialRef: "cred-1",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})
	_ = env.TrustStore.AddOrUpdateDevice(ctx, &wire.TrustRecord{
		DeviceID:          dev2,
		PublicKey:         hex.EncodeToString(pub2),
		LocalLabel:        "phone",
		PairCredentialRef: "cred-2",
		FirstSeenAt:       now,
		LastSeenAt:        now,
		Policy:            wire.DefaultTrustPolicy(),
	})

	testFile := filepath.Join(tmpDir, "report.pdf")
	if err := os.WriteFile(testFile, []byte("fake-pdf-content"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	// Invalid server URL triggers offline status for targets
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "ws://127.0.0.1:1/nonexistent",
		"--json",
		testFile,
		"@laptop",
		"@phone",
	}, &stdout, &stderr)

	// Since dialing 127.0.0.1:1 fails, all targets fail/offline -> exit code 1
	if code != 1 {
		t.Fatalf("expected exit code 1 on failed targets, got %d", code)
	}

	var res transfer.BroadcastResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("stdout was not valid json (%v): %s", err, stdout.String())
	}

	if res.AllOk {
		t.Fatal("expected AllOk=false")
	}
	if len(res.Results) != 2 {
		t.Fatalf("expected 2 target results, got %d", len(res.Results))
	}
	for _, r := range res.Results {
		if r.Status != transfer.StatusOffline && r.Status != transfer.StatusFailed {
			t.Errorf("target %s status = %s, want offline/failed", r.Label, r.Status)
		}
	}
}

func TestRenderBroadcastTable(t *testing.T) {
	results := []transfer.TargetResult{
		{
			TargetID:   "dev-1",
			Label:      "laptop",
			Status:     transfer.StatusOk,
			Digest:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			DurationMs: 450,
		},
		{
			TargetID:   "dev-2",
			Label:      "phone",
			Status:     transfer.StatusOffline,
			DurationMs: 1200,
			Error:      "peer offline",
		},
		{
			TargetID:   "dev-3",
			Label:      "workstation",
			Status:     transfer.StatusRefused,
			DurationMs: 300,
			Error:      "peer refused",
		},
	}

	var buf bytes.Buffer
	renderBroadcastTable(&buf, results, 1024*1024)
	out := buf.String()

	if !strings.Contains(out, "Broadcast Transfer Summary") {
		t.Errorf("missing header in table output: %s", out)
	}
	if !strings.Contains(out, "@laptop") || !strings.Contains(out, "@phone") || !strings.Contains(out, "@workstation") {
		t.Errorf("missing device labels in table output: %s", out)
	}
	if !strings.Contains(out, "1 succeeded, 2 failed") {
		t.Errorf("missing summary counts in table output: %s", out)
	}
}

func TestExecuteSend_PrivateFlag(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	// With an offline or fake server, executeSend should accept --private without flag error (code 1 for failed dial, not code 2 for flag parse error)
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "wss://127.0.0.1:65530/ws",
		"--private",
		testFile,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for failed dial with --private flag, got %d. stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("--private flag was not recognized: %s", stderr.String())
	}
}

func TestExecuteSend_JitterFlag(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	// With an offline or fake server, executeSend should accept --jitter without flag error
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "wss://127.0.0.1:65530/ws",
		"--jitter", "15ms",
		testFile,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1 for failed dial with --jitter flag, got %d. stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("--jitter flag was not recognized: %s", stderr.String())
	}
}

func TestExecuteSend_JSONFailure_NoSecretsExposed(t *testing.T) {
	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", "ws://127.0.0.1:1/ws?secret=supersecrettoken",
		"--json",
		testFile,
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}

	var res transfer.BroadcastResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not valid JSON (%v): %s", err, stdout.String())
	}

	if res.AllOk {
		t.Errorf("expected AllOk=false on failed send")
	}

	outStr := stdout.String()
	forbidden := []string{
		"supersecrettoken",
		"127.0.0.1:1",
		"Handshake", "handshake",
		"Master", "master",
		"Keys", "keys",
		"Spake2", "spake2",
		"Code", "code",
		"O2J", "J2O",
	}
	for _, f := range forbidden {
		if strings.Contains(outStr, `"`+f+`"`) || (f == "supersecrettoken" && strings.Contains(outStr, f)) || (f == "127.0.0.1:1" && strings.Contains(outStr, f)) {
			t.Errorf("JSON output contains forbidden string %q: %s", f, outStr)
		}
	}
}

func TestExecuteSend_JSONSuccess_NoSecretsExposed(t *testing.T) {
	srv := httptest.NewServer(newTestBlindHub())
	defer srv.Close()
	wsServerURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	tmpDir := t.TempDir()
	env, err := InitCLIEnvironment(tmpDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}

	payload := []byte("top-secret-file-content-12345678")
	testFile := filepath.Join(tmpDir, "payload.bin")
	if err := os.WriteFile(testFile, payload, 0600); err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	hasher.Write(payload)
	expectedDigest := hex.EncodeToString(hasher.Sum(nil))

	var stdout bytes.Buffer
	cw := newCodeCapturingWriter()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	joinerErrCh := make(chan error, 1)
	go func() {
		select {
		case code := <-cw.codeCh:
			joinerClient, err := wsclient.NewReconnectingSignal(ctx, wsServerURL, wsclient.DialOptions{})
			if err != nil {
				joinerErrCh <- err
				return
			}
			defer joinerClient.Close()

			recvDir := t.TempDir()
			_, err = transfer.Run(ctx, joinerClient, transfer.Spec{
				Session: rendezvous.Options{
					Role: rendezvous.RoleJoiner,
					Code: code,
				},
				DestDir:    recvDir,
				ForceRelay: true,
			})
			joinerErrCh <- err
		case <-ctx.Done():
			joinerErrCh <- ctx.Err()
		}
	}()

	sendCode := executeSend([]string{
		"--config-dir", env.ConfigDir,
		"--server", wsServerURL,
		"--relay-only",
		"--json",
		testFile,
	}, &stdout, cw)

	if sendCode != 0 {
		t.Fatalf("executeSend failed with exit code %d. stdout: %s, stderr: %s", sendCode, stdout.String(), cw.String())
	}

	select {
	case err := <-joinerErrCh:
		if err != nil {
			t.Fatalf("joiner error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for joiner")
	}

	var res transfer.BroadcastResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not valid JSON (%v): %s", err, stdout.String())
	}

	if !res.AllOk {
		t.Fatalf("expected AllOk=true, got false: %+v", res)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	r := res.Results[0]
	if r.Status != transfer.StatusOk {
		t.Errorf("status = %s, want ok", r.Status)
	}
	if r.Digest != expectedDigest {
		t.Errorf("digest = %s, want %s", r.Digest, expectedDigest)
	}
	if r.Size != int64(len(payload)) {
		t.Errorf("size = %d, want %d", r.Size, len(payload))
	}
	if r.Outcome == nil {
		t.Fatal("expected non-nil outcome")
	}
	if r.Outcome.Name != "payload.bin" {
		t.Errorf("outcome name = %s, want payload.bin", r.Outcome.Name)
	}
	if r.Outcome.Digest != expectedDigest {
		t.Errorf("outcome digest = %s, want %s", r.Outcome.Digest, expectedDigest)
	}

	jsonStr := stdout.String()
	t.Logf("executeSend --json stdout:\n%s", jsonStr)

	forbidden := []string{
		"Handshake", "handshake",
		"Master", "master",
		"Keys", "keys",
		"Spake2", "spake2",
		"Code", "code",
		"O2J", "J2O",
	}
	for _, f := range forbidden {
		if strings.Contains(jsonStr, `"`+f+`"`) {
			t.Errorf("executeSend JSON output contains forbidden field %q", f)
		}
	}
}

type codeCapturingWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	codeCh chan string
	found  bool
}

func newCodeCapturingWriter() *codeCapturingWriter {
	return &codeCapturingWriter{codeCh: make(chan string, 1)}
}

var testCodeRe = regexp.MustCompile(`\b\d+-[a-z]+(?:-[a-z]+)+\b`)

func (w *codeCapturingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err = w.buf.Write(p)
	if !w.found {
		if m := testCodeRe.FindString(w.buf.String()); m != "" {
			w.found = true
			w.codeCh <- m
		}
	}
	return n, err
}

func (w *codeCapturingWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type testBlindHub struct {
	mu    sync.Mutex
	rooms map[int]*testHubRoom
	next  int
}

type testHubRoom struct {
	offerer, joiner *testHubPeer
}

type testHubPeer struct {
	conn      *websocket.Conn
	wmu       sync.Mutex
	relayOpen bool
}

func (p *testHubPeer) send(ctx context.Context, m rendezvous.Message) {
	data, err := rendezvous.MarshalMessage(m)
	if err != nil {
		return
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, websocket.MessageText, data)
}

func (p *testHubPeer) forward(ctx context.Context, typ websocket.MessageType, data []byte) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = p.conn.Write(ctx, typ, data)
}

func newTestBlindHub() *testBlindHub {
	return &testBlindHub{rooms: make(map[int]*testHubRoom)}
}

func (h *testBlindHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	ctx := r.Context()
	self := &testHubPeer{conn: conn}

	var room *testHubRoom
	var role rendezvous.Role
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageBinary {
			h.mu.Lock()
			var other *testHubPeer
			if room != nil {
				if role == rendezvous.RoleJoiner {
					other = room.offerer
				} else {
					other = room.joiner
				}
			}
			h.mu.Unlock()
			if other != nil {
				other.forward(ctx, websocket.MessageBinary, data)
			}
			continue
		}
		msg, err := rendezvous.UnmarshalMessage(data)
		if err != nil {
			return
		}

		switch msg.Type {
		case "create":
			h.mu.Lock()
			id := h.next
			h.next++
			room = &testHubRoom{offerer: self}
			h.rooms[id] = room
			h.mu.Unlock()
			role = rendezvous.RoleOfferer
			self.send(ctx, rendezvous.Message{Type: "created", Room: &id})

		case "join":
			if msg.Room == nil {
				return
			}
			h.mu.Lock()
			room = h.rooms[*msg.Room]
			h.mu.Unlock()
			if room == nil {
				return
			}
			room.joiner = self
			role = rendezvous.RoleJoiner
			self.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleJoiner)})
			room.offerer.send(ctx, rendezvous.Message{Type: "peer-joined", Role: string(rendezvous.RoleOfferer)})

		case rendezvous.TypeRelayOpen:
			h.mu.Lock()
			self.relayOpen = true
			var other *testHubPeer
			if role == rendezvous.RoleJoiner {
				other = room.offerer
			} else {
				other = room.joiner
			}
			ready := other != nil && other.relayOpen
			h.mu.Unlock()
			if ready {
				self.send(ctx, rendezvous.Message{Type: rendezvous.TypeRelayReady})
				other.send(ctx, rendezvous.Message{Type: rendezvous.TypeRelayReady})
			} else if other != nil {
				other.send(ctx, rendezvous.Message{Type: rendezvous.TypeRelayRequired})
			}

		case rendezvous.TypeRelayCredit:
			h.mu.Lock()
			var other *testHubPeer
			if role == rendezvous.RoleJoiner {
				other = room.offerer
			} else {
				other = room.joiner
			}
			h.mu.Unlock()
			if other != nil {
				other.send(ctx, rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: msg.Bytes})
			}

		default:
			h.mu.Lock()
			var other *testHubPeer
			if room != nil {
				if role == rendezvous.RoleJoiner {
					other = room.offerer
				} else {
					other = room.joiner
				}
			}
			h.mu.Unlock()
			if other != nil {
				other.forward(ctx, typ, data)
			}
		}
	}
}
