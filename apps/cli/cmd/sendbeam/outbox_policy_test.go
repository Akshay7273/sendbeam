// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sendbeam/engine/jobs"
)

// enqueueJob runs the enqueue command with --json and returns the stored
// job id. List() sorts by random job id, so tests must never assume list
// order matches enqueue order.
func enqueueJob(t *testing.T, cfgDir, payload string, extra ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := []string{"enqueue", "--config-dir", cfgDir, "--json", payload, "--to", "@laptop"}
	args = append(args, extra...)
	if code := runOutbox(args, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}
	var summary struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil || summary.JobID == "" {
		t.Fatalf("decode enqueue json: %v output %q", err, stdout.String())
	}
	return summary.JobID
}

// TestOutboxEnqueueNetworkPolicyFlag verifies the enqueue flag binds the
// policy to the job: local-only binds, the default stays online, and an
// unknown value is rejected before anything is stored.
func TestOutboxEnqueueNetworkPolicyFlag(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "policy payload")

	localOnlyID := enqueueJob(t, cfgDir, payload, "--network-policy", "local-only")

	// Read the bound policy back through the job store.
	store, err := openOutboxStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	load := func(id string) (loaded jobs.Job) {
		t.Helper()
		loaded, ok, err := store.Load(id)
		if err != nil || !ok {
			t.Fatalf("load job %s: %v ok=%v", id, err, ok)
		}
		return loaded
	}
	if got := load(localOnlyID).EffectiveNetworkPolicy().String(); got != "local-only" {
		t.Fatalf("expected bound network policy local-only, got %q", got)
	}

	// Default enqueue stays online.
	onlineID := enqueueJob(t, cfgDir, payload)
	if got := load(onlineID).EffectiveNetworkPolicy().String(); got != "online" {
		t.Fatalf("expected default network policy online, got %q", got)
	}

	// Unknown policy is rejected before anything is stored.
	var stdout, stderr bytes.Buffer
	code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "quantum"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 for unknown policy, got %d", code)
	}
	stored, _ := store.List()
	if len(stored) != 2 {
		t.Fatalf("rejected enqueue must not store a job; have %d", len(stored))
	}
}

// TestOutboxDispatchHoldsLocalOnlyUnderOnline verifies the dispatcher
// policy gate end to end: with the default (online) effective policy, a
// local-only job is held without any send attempt — no online transfer is
// started for it, its attempts stay untouched, and the report says why.
func TestOutboxDispatchHoldsLocalOnlyUnderOnline(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "held payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "local-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	store, err := openOutboxStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	before, ok, err := store.Load(entries[0].JobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v ok=%v", err, ok)
	}
	if before.Attempts[0].Attempts != 0 {
		t.Fatalf("attempt already used before dispatch")
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "skipped") || !strings.Contains(stdout.String(), "job held") {
		t.Fatalf("expected skipped/held in dispatch report, got: %s", stdout.String())
	}

	after, ok, err := store.Load(entries[0].JobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v ok=%v", err, ok)
	}
	if after.Attempts[0].Attempts != 0 {
		t.Fatalf("held job consumed a send attempt: %d", after.Attempts[0].Attempts)
	}
	if after.Attempts[0].Status != jobs.AttemptQueued {
		t.Fatalf("held job attempt changed status to %q", after.Attempts[0].Status)
	}
}

// TestOutboxDispatchLocalOnlyRequiresPeerAddr verifies the local-only
// dispatch route fails closed when no manual endpoint is given: the job
// attempt is marked failed with the peer-addr reason rather than silently
// skipping or reaching out online.
func TestOutboxDispatchLocalOnlyRequiresPeerAddr(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "local payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "local-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir, "--network-policy", "local-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}

	store, err := openOutboxStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	stored, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	job, ok, err := store.Load(stored[0].JobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v ok=%v", err, ok)
	}
	a := job.Attempts[0]
	if a.Status == "completed" || a.Status == "verified" {
		t.Fatalf("local-only attempt without --peer-addr must not succeed; status %q", a.Status)
	}
	if !strings.Contains(a.LastError, "--peer-addr") {
		t.Fatalf("expected --peer-addr failure reason, got %q", a.LastError)
	}
}

// TestOutboxDispatchPreferLocalFallsBackOnlineExplicitly verifies the
// prefer-local contract end to end: with a live policy and a (dead) local
// endpoint, the local route is attempted first and the online fallback is
// explicit. Both legs fail here (closed port, no signaling server), so the
// attempt error must carry BOTH failures — never a silent fallback.
func TestOutboxDispatchPreferLocalFallsBackOnlineExplicitly(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "prefer-local payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "prefer-local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	// 127.0.0.1:1 is a closed port: the local attempt must fail fast, and
	// the online fallback then fails against the default local test server.
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir, "--network-policy", "prefer-local", "--peer-addr", "127.0.0.1:1"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "fell back to online") && !strings.Contains(stdout.String(), "failed") {
		t.Logf("dispatch output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	job := loadOnlyOutboxJob(t, cfgDir)
	a := job.Attempts[0]
	if a.Status == "completed" || a.Status == "verified" {
		t.Fatalf("attempt must not succeed against dead endpoints; status %q", a.Status)
	}
	if !strings.Contains(a.LastError, "local route:") {
		t.Fatalf("attempt error must name the local route failure, got %q", a.LastError)
	}
	if !strings.Contains(a.LastError, "online fallback:") {
		t.Fatalf("attempt error must name the online fallback explicitly, got %q", a.LastError)
	}
}

// TestOutboxDispatchLocalOnlyNeverFallsBack is the negative of the
// prefer-local contract: a local-only job whose local attempt fails must
// fail with the local error only — no online fallback, ever.
func TestOutboxDispatchLocalOnlyNeverFallsBack(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "local-only payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "local-only"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir, "--network-policy", "local-only", "--peer-addr", "127.0.0.1:1"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}

	job := loadOnlyOutboxJob(t, cfgDir)
	a := job.Attempts[0]
	if strings.Contains(a.LastError, "online fallback") || strings.Contains(a.LastError, "fell back to online") {
		t.Fatalf("local-only job must never fall back online; error %q", a.LastError)
	}
	if strings.Contains(stderr.String(), "fell back to online") {
		t.Fatalf("local-only dispatch must not report an online fallback: %q", stderr.String())
	}
}

// TestOutboxDispatchPreferLocalWithoutPeerAddrGoesOnlineDirectly verifies
// the honest no-endpoint behavior: with no --peer-addr there is no local
// route to prefer, so the job goes straight online without pretending a
// local attempt happened.
func TestOutboxDispatchPreferLocalWithoutPeerAddrGoesOnlineDirectly(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "prefer-local no-endpoint payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "prefer-local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir, "--network-policy", "prefer-local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}

	job := loadOnlyOutboxJob(t, cfgDir)
	a := job.Attempts[0]
	if strings.Contains(a.LastError, "local route:") {
		t.Fatalf("no local attempt should have been made without --peer-addr; error %q", a.LastError)
	}
}

// TestOutboxDispatchPreferLocalUnderOnlineGoesOnline verifies the matrix:
// a prefer-local job is dispatchable under an online effective policy —
// prefer-local permits the online route — so it is NOT held. It goes
// online directly (no local attempt under an online dispatcher) and the
// attempt is consumed normally.
func TestOutboxDispatchPreferLocalUnderOnlineGoesOnline(t *testing.T) {
	cfgDir := t.TempDir()
	env, err := InitCLIEnvironment(cfgDir)
	if err != nil {
		t.Fatalf("init cli env: %v", err)
	}
	seedOutboxDevice(t, env, "laptop")
	payload := writeOutboxFile(t, "prefer-local online payload")

	var stdout, stderr bytes.Buffer
	if code := runOutbox([]string{"enqueue", "--config-dir", cfgDir, payload, "--to", "@laptop", "--network-policy", "prefer-local"}, &stdout, &stderr); code != 0 {
		t.Fatalf("enqueue exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runOutbox([]string{"dispatch", "--config-dir", cfgDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("dispatch exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "job held") {
		t.Fatalf("prefer-local job must not be held under online; got: %s", stdout.String())
	}

	job := loadOnlyOutboxJob(t, cfgDir)
	a := job.Attempts[0]
	if a.Attempts == 0 {
		t.Fatal("the job should have been dispatched, consuming an attempt")
	}
	if strings.Contains(a.LastError, "local route:") {
		t.Fatalf("no local attempt under an online dispatcher; error %q", a.LastError)
	}
}

// loadOnlyOutboxJob loads the single job in the outbox store.
func loadOnlyOutboxJob(t *testing.T, cfgDir string) jobs.Job {
	t.Helper()
	store, err := openOutboxStore(cfgDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	stored, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 job, got %d", len(stored))
	}
	job, ok, err := store.Load(stored[0].JobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v ok=%v", err, ok)
	}
	return job
}
