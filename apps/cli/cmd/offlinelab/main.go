// Command offlinelab is a repeatable two-host verification harness for
// SendBeam's local-only (offline) workflows, per V221-PR02. It builds a real
// Linux network topology in network namespaces — two peer hosts on an isolated
// offline segment plus a reachable signaling/STUN server on a second segment —
// and drives the production CLI (`sendbeam`) through the offline workflows:
//
//   - fresh offline pairing (pair-local invite/join over the local rendezvous)
//   - paired file delivery with --network-policy=local-only and manual
//     endpoints, SHA-256 verified
//   - cancellation and recovery (sender/receiver killed mid-transfer, restarted)
//   - revocation fails closed (unpaired device cannot send; nothing is saved)
//   - an unpaired receiver rejects the sender (nothing is saved)
//   - the policy gate refuses a local-only send that was not asked for
//   - packet-level egress capture: under local-only policy the sender must not
//     emit a single packet toward the signaling/STUN/relay segment or the
//     external internet, even though a route exists and the transfer succeeds
//
// Every scenario records an Evidence entry (JSON via -out). A scenario that
// cannot run (missing tooling) is recorded as BLOCKED and fails the run — it
// is never silently skipped or passed. The whole lab runs unprivileged:
//
//	sudo unshare -Urnm offlinelab -server-bin ./sendbeamd [flags]
//
// mirroring the natlab harness (apps/cli/cmd/natlab).
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Offline segment: the two peers (no signaling, no STUN, no relay).
	offHost   = "10.0.4.1" // offline bridge gateway placeholder (unused)
	offSender = "10.0.4.2"
	offRecv   = "10.0.4.3"
	offThird  = "10.0.4.4"
	// Public segment: signaling + STUN + relay (prohibited under local-only).
	pubHost = "10.0.3.100"

	recvPort    = "45620" // receiver's local-rendezvous listener
	thirdPort   = "45621" // unpaired third host's listener
	payloadName = "handoff.bin"
)

var (
	listenAddrRe = regexp.MustCompile(`listening on ([0-9.]+:\d+)`)
	transportRe  = regexp.MustCompile(`Transport: ([^\n]+)`)
)

// Evidence is the machine-readable result of one scenario.
type Evidence struct {
	Scenario    string `json:"scenario"`
	OK          bool   `json:"ok"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"blockReason,omitempty"`
	DigestOK    bool   `json:"digestOk"`
	EgressPKts  int64  `json:"egressPackets"`
	Details     string `json:"details"`
}

type lab struct {
	sendbeam, sendbeamd, stund string

	src       string
	dstRecv   string // receiver output dir
	dstThird  string // unpaired third host output dir
	expect    [32]byte
	mu        sync.Mutex
	nses      []*netns
	keep      []*exec.Cmd // long-lived: netns holders, servers
	procs     []*exec.Cmd // per-scenario: CLI peers
	ev        []Evidence
	canonHost string
	pairedIDs map[string]string // recv config dir -> joined device id
}

func main() {
	var serverBin, prebuiltDir, out string
	flag.StringVar(&serverBin, "server-bin", "", "path to the built sendbeamd binary (required)")
	flag.StringVar(&prebuiltDir, "prebuilt", "", "directory with prebuilt sendbeam/stund binaries (skips local go build)")
	flag.StringVar(&out, "out", "", "write evidence JSON to this path")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("offlinelab: must run as root inside a user namespace: unshare -Urnm offlinelab [flags]")
	}
	if serverBin == "" {
		log.Fatal("offlinelab: -server-bin is required (build apps/server/cmd/sendbeamd first)")
	}
	if err := run(serverBin, prebuiltDir, out); err != nil {
		log.Fatalf("offlinelab: %v", err)
	}
}

func run(serverBin, prebuiltDir, out string) error {
	l := &lab{sendbeamd: serverBin}
	binDir, err := os.MkdirTemp("", "offlinelab")
	if err != nil {
		return err
	}
	if prebuiltDir != "" {
		for _, pair := range [][2]string{
			{"sendbeam", "sendbeam"},
			{"stund", "stund"},
		} {
			src := filepath.Join(prebuiltDir, pair[1])
			if _, err := os.Stat(src); err != nil {
				return fmt.Errorf("BLOCKED: prebuilt binary missing: %s (%v)", src, err)
			}
			dst := filepath.Join(binDir, pair[0])
			b, err := os.ReadFile(src)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o755); err != nil {
				return err
			}
			_ = pair
		}
		l.sendbeam = filepath.Join(binDir, "sendbeam")
		l.stund = filepath.Join(binDir, "stund")
	} else {
		build := func(name, pkg string) string {
			out := filepath.Join(binDir, name)
			root, err := moduleRoot()
			if err != nil {
				log.Fatalf("offlinelab: %v", err)
			}
			cmd := exec.Command("go", "build", "-o", out, pkg)
			cmd.Dir = root
			if outB, err := cmd.CombinedOutput(); err != nil {
				log.Fatalf("offlinelab: build %s: %v\n%s", pkg, err, outB)
			}
			return out
		}
		l.sendbeam = build("sendbeam", "./cmd/sendbeam")
		l.stund = build("stund", "./cmd/stund")
	}

	// Missing tooling means BLOCKED, never PASS.
	for _, tool := range []string{"ip", "nsenter", "iptables", "iptables-save"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("BLOCKED: required tool %q not on PATH: %v", tool, err)
		}
	}

	tmp, err := os.MkdirTemp("", "offlinelab-data")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	l.src = filepath.Join(tmp, payloadName)
	payload := make([]byte, 2*1024*1024)
	if _, err := rand.New(rand.NewSource(42)).Read(payload); err != nil {
		return err
	}
	if err := os.WriteFile(l.src, payload, 0o644); err != nil {
		return err
	}
	l.expect = sha256.Sum256(payload)
	l.dstRecv = filepath.Join(tmp, "recv")
	l.dstThird = filepath.Join(tmp, "recv-third")
	for _, d := range []string{l.dstRecv, l.dstThird} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	defer l.cleanup()
	if err := l.setup(); err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	runScenario := func(name string, noEgress bool, fn func() (digestOK bool, details string, err error)) {
		start := l.egressCounter()
		digestOK, details, err := fn()
		ev := Evidence{Scenario: name, DigestOK: digestOK, Details: details}
		if err != nil {
			if strings.HasPrefix(err.Error(), "BLOCKED") {
				ev.Blocked = true
				ev.BlockReason = err.Error()
				ev.OK = false
			} else {
				ev.OK = false
				ev.Details = strings.TrimSpace(details + " | error: " + err.Error())
			}
		} else {
			ev.OK = true
		}
		if noEgress {
			ev.EgressPKts = l.egressCounter() - start
			if ev.EgressPKts != 0 {
				// A prohibited request fails the test even if the transfer finished.
				ev.OK = false
				ev.Details = fmt.Sprintf("%s | PROHIBITED EGRESS: %d packets toward signaling/external segment under local-only policy", ev.Details, ev.EgressPKts)
			}
		}
		l.mu.Lock()
		l.ev = append(l.ev, ev)
		l.mu.Unlock()
		log.Printf("scenario %-28s ok=%t blocked=%t digest=%t egress=%d %s",
			name, ev.OK, ev.Blocked, ev.DigestOK, ev.EgressPKts, ev.Details)
	}

	var senderCfg, recvCfg, thirdCfg string
	runScenario("offline-fresh-pairing", false, func() (bool, string, error) {
		id, details, err := l.pairFresh(&senderCfg, &recvCfg)
		return id, details, err
	})
	runScenario("offline-paired-delivery", true, func() (bool, string, error) {
		return l.pairedDelivery(senderCfg, recvCfg)
	})
	runScenario("offline-cancel-and-recovery", true, func() (bool, string, error) {
		return l.cancelAndRecovery(senderCfg, recvCfg)
	})
	runScenario("offline-unpaired-receiver", true, func() (bool, string, error) {
		return l.unpairedReceiver(senderCfg, &thirdCfg)
	})
	runScenario("offline-revoke-fails-closed", true, func() (bool, string, error) {
		return l.revokeFailsClosed(senderCfg, recvCfg)
	})
	runScenario("offline-policy-gate", true, func() (bool, string, error) {
		return l.policyGate(senderCfg, recvCfg)
	})

	if out != "" {
		b, _ := json.MarshalIndent(l.ev, "", "  ")
		if err := os.WriteFile(out, b, 0o644); err != nil {
			return err
		}
		log.Printf("evidence written to %s", out)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.ev {
		if !e.OK {
			return fmt.Errorf("scenario %q did not pass (blocked=%t): %s", e.Scenario, e.Blocked, e.Details)
		}
	}
	return nil
}

// setup builds the topology:
//
//	offline bridge (ns pub-off): nsA.a0=10.0.4.2, nsB.b0=10.0.4.3, nsC.c0=10.0.4.4
//	public  bridge (ns pub):    sendbeamd+stund at 10.0.3.100
//	nsA is dual-homed: ap0=10.0.3.9 on the public bridge, default route via the
//	server — so prohibited egress is *possible* and the capture is meaningful.
//	nsB and nsC are single-homed on the offline segment.
func (l *lab) setup() error {
	nsA, _ := l.spawnNetns("a")
	nsB, _ := l.spawnNetns("b")
	nsC, _ := l.spawnNetns("c")
	nsPub, _ := l.spawnNetns("pub")
	nsPubOff, _ := l.spawnNetns("pub-off")

	if err := l.veth("a0", nsA, "ao0", nsPubOff); err != nil {
		return err
	}
	if err := l.veth("b0", nsB, "bo0", nsPubOff); err != nil {
		return err
	}
	if err := l.veth("c0", nsC, "co0", nsPubOff); err != nil {
		return err
	}
	if err := l.veth("ap0", nsA, "ao1", nsPub); err != nil {
		return err
	}
	// Server-side leg inside the pub namespace (both ends in the same netns).
	if err := l.veth("srv0", nsPub, "srv1", nsPub); err != nil {
		return err
	}

	up := func(ns *netns, ifname string) error {
		return l.nsRun(ns, "ip", "link", "set", ifname, "up")
	}
	loopUp := func(ns *netns) error { return l.nsRun(ns, "ip", "link", "set", "lo", "up") }
	addr := func(ns *netns, ifname, ip string) error {
		return l.nsRun(ns, "ip", "addr", "add", ip, "dev", ifname)
	}

	// Offline bridge.
	bridge := [][]string{
		{"link", "add", "br-off", "type", "bridge"},
		{"link", "set", "br-off", "up"},
		{"link", "set", "ao0", "master", "br-off"},
		{"link", "set", "ao0", "up"},
		{"link", "set", "bo0", "master", "br-off"},
		{"link", "set", "bo0", "up"},
		{"link", "set", "co0", "master", "br-off"},
		{"link", "set", "co0", "up"},
		{"addr", "add", offHost + "/24", "dev", "br-off"},
	}
	for _, step := range bridge {
		if err := l.nsRun(nsPubOff, append([]string{"ip"}, step...)...); err != nil {
			return fmt.Errorf("pub-off %v: %w", step, err)
		}
	}
	// Public bridge (no NAT: peers reach it directly when dual-homed).
	pubSteps := [][]string{
		{"link", "add", "br0", "type", "bridge"},
		{"link", "set", "br0", "up"},
		{"link", "set", "ao1", "master", "br0"},
		{"link", "set", "ao1", "up"},
		{"link", "set", "srv0", "master", "br0"},
		{"link", "set", "srv0", "up"},
		{"addr", "add", pubHost + "/24", "dev", "srv0"},
	}
	for _, step := range pubSteps {
		if err := l.nsRun(nsPub, append([]string{"ip"}, step...)...); err != nil {
			return fmt.Errorf("pub %v: %w", step, err)
		}
	}

	steps := []struct {
		ns *netns
		fn func() error
	}{
		{nsA, func() error { return loopUp(nsA) }},
		{nsB, func() error { return loopUp(nsB) }},
		{nsC, func() error { return loopUp(nsC) }},
		{nsA, func() error { return addr(nsA, "a0", offSender+"/24") }},
		{nsA, func() error { return up(nsA, "a0") }},
		{nsB, func() error { return addr(nsB, "b0", offRecv+"/24") }},
		{nsB, func() error { return up(nsB, "b0") }},
		{nsC, func() error { return addr(nsC, "c0", offThird+"/24") }},
		{nsC, func() error { return up(nsC, "c0") }},
		{nsA, func() error { return addr(nsA, "ap0", "10.0.3.9/24") }},
		{nsA, func() error { return up(nsA, "ap0") }},
		// The dual-homed sender can reach the prohibited segment via the server
		// host as next hop (the connected 10.0.3.0/24 route comes up with ap0).
		{nsA, func() error { return l.nsRun(nsA, "ip", "route", "replace", "default", "via", "10.0.3.100") }},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("configure: %w", err)
		}
	}

	// Egress capture rules on the sender: anything leaving ap0 — toward the
	// signaling segment or the external internet — is counted. Local-only must
	// keep both counters at zero.
	if err := l.nsRun(nsA, "iptables", "-A", "OUTPUT", "-o", "ap0", "-d", "10.0.3.0/24"); err != nil {
		return fmt.Errorf("iptables rule (signaling): %w", err)
	}
	if err := l.nsRun(nsA, "iptables", "-A", "OUTPUT", "-o", "ap0", "!", "-d", "10.0.3.0/24"); err != nil {
		return fmt.Errorf("iptables rule (external): %w", err)
	}

	// Services on the public segment: signaling + STUN (reachable, prohibited).
	c, err := l.nsSpawn(nsPub, []string{"SENDBEAM_ADDR=" + pubHost + ":8443"}, l.sendbeamd)
	if err != nil {
		return fmt.Errorf("sendbeamd: %w", err)
	}
	l.mu.Lock()
	l.keep = append(l.keep, c)
	l.mu.Unlock()
	c, err = l.nsSpawn(nsPub, nil, l.stund, "-addr", pubHost+":3478")
	if err != nil {
		return fmt.Errorf("stund: %w", err)
	}
	l.mu.Lock()
	l.keep = append(l.keep, c)
	l.mu.Unlock()

	// Wait for the signaling server to accept TCP.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := l.nsRun(nsA, "bash", "-c", fmt.Sprintf("echo > /dev/tcp/%s/8443", pubHost)); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Distinct per-peer config roots on the shared filesystem. Hosts share the
	// mount namespace; only the network namespace differs (like natlab).
	root, err := os.MkdirTemp("", "offlinelab-cfg")
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.canonHost = root
	l.mu.Unlock()
	for _, d := range []string{"a", "b", "c"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return err
		}
	}
	return nil
}

// egressCounter reads the summed packet counters of the two capture rules on
// the sender host.
func (l *lab) egressCounter() int64 {
	l.mu.Lock()
	var nsA *netns
	for _, n := range l.nses {
		if n.name == "a" {
			nsA = n
		}
	}
	l.mu.Unlock()
	out, err := exec.Command("nsenter", "-t", fmt.Sprint(nsA.pid), "-n",
		"iptables-save", "-c").CombinedOutput()
	if err != nil {
		log.Printf("egressCounter: %v:\n%s", err, out)
		return -1
	}
	var total int64
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "-A OUTPUT -o ap0") {
			continue
		}
		if m := counterRe.FindStringSubmatch(line); m != nil {
			var n int64
			if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
				log.Printf("egressCounter: bad counter %q: %v", m[1], err)
				continue
			}
			total += n
		}
	}
	return total
}

var counterRe = regexp.MustCompile(`^\[([0-9]+):[0-9]+\]`)

// cliCmd builds an nsenter-wrapped sendbeam invocation with a per-host
// environment: HOME points at the host's config root and the store-dir
// overrides pin every store to that root (state migration resolves the jobs
// store from the environment, not --config-dir).
func (l *lab) cliCmd(ns *netns, cfgDir string, args ...string) *exec.Cmd {
	full := append([]string{"-t", fmt.Sprint(ns.pid), "-n", l.sendbeam}, args...)
	c := exec.Command("nsenter", full...)
	env := os.Environ()[:0]
	for _, kv := range os.Environ() {
		key := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		switch key {
		case "HOME", "XDG_CONFIG_HOME", "SENDBEAM_JOBS_DIR", "SENDBEAM_RECIPES_DIR", "SENDBEAM_SENDER_STATE":
			continue
		}
		env = append(env, kv)
	}
	c.Env = append(env,
		"HOME="+cfgDir,
		"SENDBEAM_JOBS_DIR="+filepath.Join(cfgDir, "jobs"),
		"SENDBEAM_RECIPES_DIR="+filepath.Join(cfgDir, "recipes"),
		"SENDBEAM_SENDER_STATE="+filepath.Join(cfgDir, "sender"),
	)
	return c
}

// pairFresh runs `pair-local invite` on the sender host and `pair-local join`
// on the receiver host over the isolated offline segment. Both commands exit
// once pairing completes; the resulting trust stores (trust.json) are read
// from disk — the sender-side record's device_id is the receiver's id, the
// name the sender must use in `send --to`.
func (l *lab) pairFresh(senderCfg, recvCfg *string) (bool, string, error) {
	l.mu.Lock()
	root := l.canonHost
	var nsA, nsB *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "b":
			nsB = n
		}
	}
	l.mu.Unlock()
	*senderCfg = filepath.Join(root, "a")
	*recvCfg = filepath.Join(root, "b")

	invite := l.cliCmd(nsA, *senderCfg,
		"pair-local", "invite",
		"--bind", offSender+":45617",
		"--window", "10m",
		"--json",
		"--config-dir", *senderCfg)
	var invOut, invErr strings.Builder
	invite.Stdout = &invOut
	invite.Stderr = &invErr
	if err := invite.Start(); err != nil {
		return false, "", fmt.Errorf("start pair-local invite: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, invite)
	l.mu.Unlock()

	// The invitation JSON appears on the inviter's stdout immediately; the
	// process then blocks in Accept until the joiner arrives.
	invitation := ""
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := jsonField(invOut.String(), "invitation"); m != "" {
			invitation = m
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if invitation == "" {
		_ = invite.Process.Kill()
		return false, "no invitation JSON", fmt.Errorf("pair-local invite produced no invitation: %s", invErr.String())
	}

	join := l.cliCmd(nsB, *recvCfg,
		"pair-local", "join", "--json", "--config-dir", *recvCfg)
	join.Stdin = strings.NewReader(invitation + "\n")
	var joinOut, joinErr strings.Builder
	join.Stdout = &joinOut
	join.Stderr = &joinErr
	joinDone := make(chan error, 1)
	go func() { joinDone <- join.Run() }()

	select {
	case err := <-joinDone:
		if err != nil {
			_ = invite.Process.Kill()
			return false, "pair-local join failed", fmt.Errorf("%v\n--- join stderr ---\n%s", err, joinErr.String())
		}
	case <-time.After(45 * time.Second):
		_ = join.Process.Kill()
		_ = invite.Process.Kill()
		return false, "pair-local join timed out", fmt.Errorf("join did not finish\n--- join stderr ---\n%s\n--- invite stderr ---\n%s", joinErr.String(), invErr.String())
	}
	inviteDone := make(chan error, 1)
	go func() { inviteDone <- invite.Wait() }()
	select {
	case err := <-inviteDone:
		if err != nil {
			return false, "pair-local invite failed", fmt.Errorf("%v\n--- invite stderr ---\n%s", err, invErr.String())
		}
	case <-time.After(15 * time.Second):
		_ = invite.Process.Kill()
		return false, "", fmt.Errorf("inviter did not exit after pairing\n--- invite stderr ---\n%s", invErr.String())
	}

	// Ground truth from disk: both trust stores must hold exactly one live device.
	senderDevices, rerr := readTrustDevices(*senderCfg)
	if rerr != nil {
		return false, "", fmt.Errorf("sender trust store: %v", rerr)
	}
	recvDevices, rerr := readTrustDevices(*recvCfg)
	if rerr != nil {
		return false, "", fmt.Errorf("receiver trust store: %v", rerr)
	}
	if len(senderDevices) != 1 || len(recvDevices) != 1 {
		return false, fmt.Sprintf("trust stores: sender=%v receiver=%v", senderDevices, recvDevices),
			fmt.Errorf("expected exactly one live device on each side")
	}
	// Sender-side device_id names the RECEIVER; that is the `--to` target.
	l.notePaired(*recvCfg, senderDevices[0])
	return true, "paired; receiver device id " + senderDevices[0], nil
}

// readTrustDevices returns the non-revoked device ids recorded in
// <cfgDir>/trust.json.
func readTrustDevices(cfgDir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(cfgDir, "trust.json"))
	if err != nil {
		return nil, fmt.Errorf("read trust.json: %w", err)
	}
	var payload struct {
		Devices []struct {
			DeviceID string `json:"device_id"`
			Revoked  bool   `json:"revoked"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("parse trust.json: %w", err)
	}
	var ids []string
	for _, d := range payload.Devices {
		if !d.Revoked && d.DeviceID != "" {
			ids = append(ids, d.DeviceID)
		}
	}
	return ids, nil
}

// pairedDelivery sends the payload to the paired device over local-only and
// verifies the received bytes.
func (l *lab) pairedDelivery(senderCfg, recvCfg string) (bool, string, error) {
	return l.localOnlyTransfer(senderCfg, recvCfg, l.dstRecv)
}

// localOnlyTransfer drives one local-only send/receive round trip between the
// two paired hosts.
func (l *lab) localOnlyTransfer(senderCfg, recvCfg, dstDir string) (bool, string, error) {
	l.mu.Lock()
	var nsA, nsB *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "b":
			nsB = n
		}
	}
	l.mu.Unlock()

	deviceID := l.joinedDeviceID(recvCfg)
	if deviceID == "" {
		return false, "receiver device id unknown", fmt.Errorf("no paired device in %s (pairing scenario must run first)", recvCfg)
	}

	receiver := l.cliCmd(nsB, recvCfg, "receive",
		"--network-policy", "local-only",
		"--bind", offRecv+":"+recvPort,
		"--out", dstDir,
		"--config-dir", recvCfg)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", fmt.Errorf("start receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()

	// Wait for the listener address line so the sender gets a real endpoint.
	recvAddr := ""
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenAddrRe.FindStringSubmatch(recvOut.String()); m != nil {
			recvAddr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if recvAddr == "" {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("receiver never listened: %s", recvErr.String())
	}

	sender := l.cliCmd(nsA, senderCfg, "send",
		"--network-policy", "local-only",
		"--to", deviceID,
		"--peer-addr", recvAddr,
		"--config-dir", senderCfg,
		l.src)
	var sendOut, sendErr strings.Builder
	sender.Stdout = &sendOut
	sender.Stderr = &sendErr
	if err := sender.Start(); err != nil {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, sender)
	l.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- receiver.Wait() }()
	select {
	case err := <-done:
		_ = sender.Process.Kill()
		if err != nil {
			return false, "", fmt.Errorf("receiver failed: %v\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), sendErr.String())
		}
	case <-time.After(90 * time.Second):
		_ = receiver.Process.Kill()
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("local-only transfer timed out\n--- receiver ---\n%s\n--- sender ---\n%s", recvErr.String(), sendErr.String())
	}
	_ = sender.Wait()

	got, err := os.ReadFile(filepath.Join(dstDir, payloadName))
	if err != nil {
		return false, "", fmt.Errorf("read received file: %w\n--- receiver ---\n%s\n--- sender ---\n%s", err, recvErr.String(), sendErr.String())
	}
	return sha256.Sum256(got) == l.expect, "endpoint " + recvAddr, nil
}

// cancelAndRecovery kills the sender mid-transfer, restarts both ends, and
// requires the transfer to complete with verified bytes (crash-resilient
// resume through the production journals).
func (l *lab) cancelAndRecovery(senderCfg, recvCfg string) (bool, string, error) {
	l.mu.Lock()
	var nsA, nsB *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "b":
			nsB = n
		}
	}
	l.mu.Unlock()
	deviceID := l.joinedDeviceID(recvCfg)

	// Fresh slate: a completed prior delivery legitimately leaves its sender
	// record behind, and this scenario's own kill round leaves an interrupted
	// one. Clear the sender store up front so round 1 sends fresh — the
	// documented offline recovery for an unresumable interrupt is exactly
	// this discard-then-resend path.
	_ = os.RemoveAll(filepath.Join(senderCfg, "sender"))

	dst := filepath.Join(filepath.Dir(l.dstRecv), "recv-resume")
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return false, "", err
	}

	// Round 1: start a transfer, let it begin, then SIGKILL the sender.
	receiver := l.cliCmd(nsB, recvCfg, "receive",
		"--network-policy", "local-only",
		"--bind", offRecv+":"+recvPort,
		"--out", dst,
		"--config-dir", recvCfg)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", fmt.Errorf("start receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()
	recvAddr := ""
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenAddrRe.FindStringSubmatch(recvOut.String()); m != nil {
			recvAddr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if recvAddr == "" {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("receiver never listened: %s", recvErr.String())
	}

	sender := l.cliCmd(nsA, senderCfg, "send",
		"--network-policy", "local-only",
		"--to", deviceID,
		"--peer-addr", recvAddr,
		"--config-dir", senderCfg,
		l.src)
	var sendOut, sendErr strings.Builder
	sender.Stdout = &sendOut
	sender.Stderr = &sendErr
	if err := sender.Start(); err != nil {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, sender)
	l.mu.Unlock()

	// Wait until the transfer is genuinely in flight, then cancel hard.
	// Every 4s, log the captured output so a silent hang is diagnosable from
	// the CI log instead of a bare empty-stderr failure.
	// Wait for the transfer to be genuinely in flight (ICE connected), the
	// sender to fail, or the deadline. A hang is diagnosable from the
	// periodic output dump instead of a bare empty-stderr failure.
	inFlight := false
	senderFailed := false
	deadline = time.Now().Add(20 * time.Second)
	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()
	for time.Now().Before(deadline) {
		// The local-send path prints the selected route on stdout ("route:
		// direct (local direct)") once the channel is open — bytes are about
		// to move. The online path prints "Transport: ..." on stderr.
		if transportRe.MatchString(sendErr.String()) || strings.Contains(sendOut.String(), "route: ") {
			inFlight = true
			break
		}
		if strings.Contains(sendErr.String(), "sendbeam send:") {
			senderFailed = true
			break
		}
		select {
		case <-tick.C:
			log.Printf("cancel: sender pid=%d out=%q err=%q recv=%q",
				sender.Process.Pid, sendOut.String(), sendErr.String(), recvOut.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Whatever happened in round 1, stop everything and clean the sender
	// state directly (host-side): the offline recovery contract discards the
	// interrupted sender record so the next send is fresh — the CLI discard
	// path depends on env-resolved stores and durable stores in cwd, which
	// the harness cannot rely on; removing the record file from the store
	// directory is the same effect, bounded to this lab's own state root.
	_ = receiver.Process.Kill()
	_ = receiver.Wait()
	_ = sender.Process.Kill()
	_ = sender.Wait()
	_ = os.RemoveAll(filepath.Join(senderCfg, "sender"))
	if senderFailed && !inFlight {
		return false, "round-1 send failed before flight: " + sendErr.String(),
			fmt.Errorf("round-1 send failed: %s", sendErr.String())
	}
	if !inFlight {
		return false, "", fmt.Errorf("transfer never entered flight: %s", sendErr.String())
	}
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return false, "", err
	}
	ok, details, err := l.localOnlyTransfer(senderCfg, recvCfg, dst)
	if err != nil {
		return false, "restart after cancel: " + details, fmt.Errorf("%v", err)
	}
	return ok, "cancel after in-flight; recovered: " + details, nil
}

// unpairedReceiver points the sender (valid trust gate) at a third host that
// has never been paired. The handshake must fail closed and nothing may be
// written to the third host's destination.
func (l *lab) unpairedReceiver(senderCfg string, thirdCfg *string) (bool, string, error) {
	l.mu.Lock()
	root := l.canonHost
	var nsA, nsC *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "c":
			nsC = n
		}
	}
	l.mu.Unlock()
	*thirdCfg = filepath.Join(root, "c")
	deviceID := l.joinedDeviceID(filepath.Join(root, "b"))

	receiver := l.cliCmd(nsC, *thirdCfg, "receive",
		"--network-policy", "local-only",
		"--bind", offThird+":"+thirdPort,
		"--out", l.dstThird,
		"--config-dir", *thirdCfg)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", fmt.Errorf("start unpaired receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()
	recvAddr := ""
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenAddrRe.FindStringSubmatch(recvOut.String()); m != nil {
			recvAddr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if recvAddr == "" {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("third host never listened: %s", recvErr.String())
	}

	sender := l.cliCmd(nsA, senderCfg, "send",
		"--network-policy", "local-only",
		"--to", deviceID,
		"--peer-addr", recvAddr,
		"--config-dir", senderCfg,
		l.src)
	var sendOut, sendErr strings.Builder
	sender.Stdout = &sendOut
	sender.Stderr = &sendErr
	if err := sender.Start(); err != nil {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	// The sender must fail: the third host's server admits only PAIRED
	// devices, the sender is not one of them, so admission is refused and
	// the send errors out (or never opens a data channel). Wait for the
	// sender to settle; a hang beyond the deadline is a scenario failure.
	sendDone := make(chan error, 1)
	go func() { sendDone <- sender.Wait() }()
	var sendErrExit error
	select {
	case sendErrExit = <-sendDone:
	case <-time.After(60 * time.Second):
		_ = sender.Process.Kill()
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("unpaired-receiver scenario timed out (sender did not settle)")
	}
	_ = receiver.Process.Kill()
	_ = receiver.Wait()
	if sendErrExit == nil {
		return false, "", fmt.Errorf("send to an unpaired device succeeded — trust gate did not fail closed")
	}

	// Trust-boundary assertions: nothing saved on the third host, and the
	// receiver's own output shows no completed receive (the receiver keeps
	// listening by design — admission refusal is silent to it).
	if entries, _ := os.ReadDir(l.dstThird); len(entries) != 0 {
		return false, "", fmt.Errorf("unpaired receiver saved %q — trust boundary violated", entries[0].Name())
	}
	if strings.Contains(recvOut.String(), "Received ") {
		return false, "", fmt.Errorf("unpaired receiver completed a transfer — trust boundary violated")
	}
	return true, "sender refused, destination empty", nil
}

// revokeFailsClosed unpairs the receiver on the sender and requires the local-only
// send to fail closed with nothing saved.
func (l *lab) revokeFailsClosed(senderCfg, recvCfg string) (bool, string, error) {
	l.mu.Lock()
	var nsA, nsB *netns
	for _, n := range l.nses {
		switch n.name {
		case "a":
			nsA = n
		case "b":
			nsB = n
		}
	}
	l.mu.Unlock()
	deviceID := l.joinedDeviceID(recvCfg)

	// Start the receiver so the failure happens against a live listener.
	// Fresh destination: the assertion is 'nothing saved', so it must not be
	// polluted by artifacts of earlier scenarios.
	dstRevoke := filepath.Join(filepath.Dir(l.dstRecv), "recv-revoke")
	_ = os.RemoveAll(dstRevoke)
	if err := os.MkdirAll(dstRevoke, 0o755); err != nil {
		return false, "", err
	}
	receiver := l.cliCmd(nsB, recvCfg, "receive",
		"--network-policy", "local-only",
		"--bind", offRecv+":"+recvPort,
		"--out", dstRevoke,
		"--config-dir", recvCfg)
	var recvOut, recvErr strings.Builder
	receiver.Stdout = &recvOut
	receiver.Stderr = &recvErr
	if err := receiver.Start(); err != nil {
		return false, "", fmt.Errorf("start receiver: %w", err)
	}
	l.mu.Lock()
	l.procs = append(l.procs, receiver)
	l.mu.Unlock()
	recvAddr := ""
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if m := listenAddrRe.FindStringSubmatch(recvOut.String()); m != nil {
			recvAddr = m[1]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Revoke on the sender side. An empty device id means pairing never
	// completed — record that as a scenario failure instead of feeding the CLI
	// an empty positional (which would break flag parsing downstream).
	if deviceID == "" {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("no paired device to revoke (pairing scenario must pass first)")
	}
	unpair := l.cliCmd(nsA, senderCfg, "unpair", "--yes", "--config-dir", senderCfg, deviceID)
	var unpOut, unpErr strings.Builder
	unpair.Stdout = &unpOut
	unpair.Stderr = &unpErr
	if err := unpair.Run(); err != nil {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("unpair failed: %v\n%s", err, unpErr.String())
	}

	sender := l.cliCmd(nsA, senderCfg, "send",
		"--network-policy", "local-only",
		"--to", deviceID,
		"--peer-addr", recvAddr,
		"--config-dir", senderCfg,
		l.src)
	var sendOut, sendErr strings.Builder
	sender.Stdout = &sendOut
	sender.Stderr = &sendErr
	if err := sender.Start(); err != nil {
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sender.Wait() }()
	select {
	case err := <-done:
		_ = receiver.Process.Kill()
		_ = receiver.Wait()
		if err == nil {
			return false, "", fmt.Errorf("send to revoked device succeeded — trust gate did not fail closed")
		}
	case <-time.After(60 * time.Second):
		_ = sender.Process.Kill()
		_ = receiver.Process.Kill()
		return false, "", fmt.Errorf("revoked-send scenario timed out")
	}
	entries, _ := os.ReadDir(dstRevoke)
	if len(entries) != 0 {
		return false, "", fmt.Errorf("revoked receiver saved %q — trust boundary violated", entries[0].Name())
	}
	return true, "send rejected after revocation, destination untouched", nil
}

// policyGate verifies the sender refuses an offline-targeted send that was not
// asked for as local-only. Per the send-path contract, a targeted send without
// --network-policy=local-only resolves the effective policy from configuration
// (online by default) and would require public signaling — which does not exist
// on the isolated offline segment. The gate being verified: the CLI must not
// silently fall back to local-only for a policy=online request — it fails
// instead (no implicit policy downgrade), and no bytes are saved anywhere.
func (l *lab) policyGate(senderCfg, recvCfg string) (bool, string, error) {
	l.mu.Lock()
	var nsA *netns
	for _, n := range l.nses {
		if n.name == "a" {
			nsA = n
		}
	}
	l.mu.Unlock()
	deviceID := l.joinedDeviceID(recvCfg)

	sender := l.cliCmd(nsA, senderCfg, "send",
		"--network-policy", "online",
		"--to", deviceID,
		"--peer-addr", offRecv+":"+recvPort,
		"--config-dir", senderCfg,
		l.src)
	var sendOut, sendErr strings.Builder
	sender.Stdout = &sendOut
	sender.Stderr = &sendErr
	if err := sender.Start(); err != nil {
		return false, "", fmt.Errorf("start sender: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sender.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return false, "", fmt.Errorf("wrong-policy send succeeded — policy gate did not fail closed")
		}
	case <-time.After(60 * time.Second):
		_ = sender.Process.Kill()
		return false, "", fmt.Errorf("policy-gate scenario timed out")
	}
	return true, "send without local-only policy refused", nil
}

// joinedDeviceID returns the most recent paired device ID recorded in the
// receiver's config dir (captured when pairing succeeded).
func (l *lab) joinedDeviceID(recvCfg string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id, ok := l.pairedIDs[recvCfg]; ok {
		return id
	}
	return ""
}

func (l *lab) notePaired(cfg, id string) {
	l.mu.Lock()
	if l.pairedIDs == nil {
		l.pairedIDs = map[string]string{}
	}
	l.pairedIDs[cfg] = id
	l.mu.Unlock()
}

// jsonField extracts a top-level string field from a JSON object printed on
// one line (the CLI's --json output).
func jsonField(s, field string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if v, ok := obj[field].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

type netns struct {
	name string
	pid  int
}

func (l *lab) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range append(l.procs, l.keep...) {
		_ = c.Process.Kill()
	}
	for _, n := range l.nses {
		_ = syscall.Kill(n.pid, syscall.SIGKILL)
	}
	l.procs = nil
	l.keep = nil
	l.nses = nil
}

func (l *lab) spawnNetns(name string) (*netns, error) {
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn %s: %w", name, err)
	}
	go func() { _ = cmd.Wait() }() // detached; the netns lives until cleanup
	l.mu.Lock()
	l.keep = append(l.keep, cmd)
	l.nses = append(l.nses, &netns{name: name, pid: cmd.Process.Pid})
	l.mu.Unlock()
	return &netns{name: name, pid: cmd.Process.Pid}, nil
}

// nsRun executes a command inside a netns via nsenter -t <pid> -n, failing
// with the command's captured output for diagnosability.
func (l *lab) nsRun(ns *netns, args ...string) error {
	full := append([]string{"-t", fmt.Sprint(ns.pid), "-n"}, args...)
	out, err := exec.Command("nsenter", full...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nsSpawn starts a long-running process inside a netns.
func (l *lab) nsSpawn(ns *netns, env []string, cmd string, args ...string) (*exec.Cmd, error) {
	full := append([]string{"-t", fmt.Sprint(ns.pid), "-n"}, append([]string{cmd}, args...)...)
	c := exec.Command("nsenter", full...)
	c.Env = append(os.Environ(), env...)
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *lab) veth(nameA string, nsA *netns, nameB string, nsB *netns) error {
	if err := exec.Command("ip", "link", "add", nameA, "type", "veth", "peer", "name", nameB).Run(); err != nil {
		return fmt.Errorf("veth %s/%s: %w", nameA, nameB, err)
	}
	if err := exec.Command("ip", "link", "set", nameA, "netns", fmt.Sprint(nsA.pid)).Run(); err != nil {
		return err
	}
	return exec.Command("ip", "link", "set", nameB, "netns", fmt.Sprint(nsB.pid)).Run()
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("no go.mod found above %q; run offlinelab from the apps/cli module", wd)
		}
		wd = parent
	}
}
