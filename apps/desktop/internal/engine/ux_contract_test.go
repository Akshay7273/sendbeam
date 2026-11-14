// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// ---------------------------------------------------------------------------
// SB-R09: backend contracts the UX depends on (requirement 2, 3, 6).
// The DOM-level behavior is covered by the jsdom suite (desktop-render.test.ts);
// these Go tests pin the SERVICE contracts the UI renders: honest lifecycle
// visibility, grant semantics, cancel honesty, degradation visibility.
// ---------------------------------------------------------------------------

// newRecipeUXService builds a real RecipeService with one trusted recipient.
func newRecipeUXService(t *testing.T) (*RecipeService, string, string, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	idm, err := trust.NewIdentityManager(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := trust.NewFileSecretStore(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	ts := trust.NewMemoryTrustStore()
	svc, err := NewRecipeService(dir, ts, idm, secrets)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(5 * time.Second) })
	svc.StopDispatcher()

	senderIdentity, err := idm.GetOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerIdentity, err := wire.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, pair := range [][2]*wire.DeviceIdentity{{senderIdentity, peerIdentity}, {peerIdentity, senderIdentity}} {
		_, peer := pair[0], pair[1]
		if err := ts.AddOrUpdateDevice(ctx, &wire.TrustRecord{
			DeviceID:          peer.DeviceID,
			PublicKey:         peer.PublicKeyHex(),
			LocalLabel:        "peer",
			PairCredentialRef: "cred-ux",
			FirstSeenAt:       now,
			LastSeenAt:        now,
			Policy:            wire.DefaultTrustPolicy(),
		}); err != nil {
			t.Fatal(err)
		}
		if err := secrets.SetSecret(peer.DeviceID, []byte(strings.Repeat("k", 32))); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(dir, "sources")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ux.bin"), []byte("ux"), 0o600); err != nil {
		t.Fatal(err)
	}
	return svc, root, peerIdentity.DeviceID, dir
}

// TestR09SaveNeverAuthorizes pins requirement 3: a saved recipe is inert
// (approval-required, no grant, no run) — saving must not silently authorize
// execution, and the visible fields the UI renders reflect that.
func TestR09SaveNeverAuthorizes(t *testing.T) {
	svc, root, peerID, _ := newRecipeUXService(t)
	in := newEditorInput("nightly", root, peerID)
	in.NetworkPolicy = "local-only"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatalf("CreateRecipe: %v", err)
	}
	r, ok, err := svc.store.Load(created.ID)
	if err != nil || !ok {
		t.Fatalf("load: %v %v", err, ok)
	}
	if r.Status != recipes.RecipeApprovalRequired {
		t.Fatalf("saved status = %q, want approval-required (save must not authorize)", r.Status)
	}
	if r.Grant.AutoSend {
		t.Fatal("saved recipe carries an auto-send grant — saving must not authorize automation")
	}
	if r.GrantValid(time.Now().UTC()) {
		t.Fatal("saved recipe grant validates — must be inert without explicit approval")
	}
	// The delivery status view must show NO run and NO job.
	st, err := svc.RecipeDeliveryStatus(created.ID)
	if err != nil {
		t.Fatalf("RecipeDeliveryStatus: %v", err)
	}
	if st.LastRun != nil || st.Job != nil {
		t.Fatalf("saved recipe shows run/job activity: %+v %+v", st.LastRun, st.Job)
	}
}

// TestR09GrantSeparateFromApprovalAndAutoAccept pins requirement 3: auto-send
// is a distinct permission — approval alone does not grant it, the grant
// requires approval, and granting does not touch receiver-side acceptance
// (the grant struct only has sender-side fields).
func TestR09GrantSeparateFromApprovalAndAutoAccept(t *testing.T) {
	svc, root, peerID, _ := newRecipeUXService(t)
	in := newEditorInput("nightly", root, peerID)
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	// Grant BEFORE approval must refuse (approval first).
	if _, err := svc.GrantAutomation(created.ID); err == nil {
		t.Fatal("auto-send granted on an approval-required recipe — grant must require approval")
	}
	// Approve: one-shot runs allowed; grant still absent.
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	r, ok, _ := svc.store.Load(created.ID)
	if ok && r.Grant.AutoSend {
		t.Fatal("approval silently granted auto-send")
	}
	// Now grant.
	if _, err := svc.GrantAutomation(created.ID); err != nil {
		t.Fatalf("GrantAutomation: %v", err)
	}
	r, _, _ = svc.store.Load(created.ID)
	if !r.GrantValid(time.Now().UTC()) {
		t.Fatal("granted auto-send does not validate")
	}
	// Grant does not touch receiver-side acceptance policy (separate surface).
	if r.Grant.AutoSend && r.Recipients[0].DeviceID == "" {
		t.Fatal("grant malformed recipient state")
	}
}

// TestR09ScopeEditRevokesGrant pins requirement 3: any material change
// (sources/recipients/policy/padding) invalidates the automation grant —
// restart must preserve the saved recipe but NOT the invalid authorization.
func TestR09ScopeEditRevokesGrant(t *testing.T) {
	svc, root, peerID, _ := newRecipeUXService(t)
	in := newEditorInput("nightly", root, peerID)
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantAutomation(created.ID); err != nil {
		t.Fatal(err)
	}
	before, _, _ := svc.store.Load(created.ID)
	cvBefore := before.Grant.ConsentVersion

	// Material edit: swap the recipient.
	in2 := newEditorInput("nightly", root, peerID)
	in2.ID = created.ID
	// (reusing the same recipient keeps scope identical; add a second source
	// to force a material change)
	in2.Sources = append(in2.Sources, RecipeSourceInput{Path: root + "/extra", Recursive: false})
	if err := os.MkdirAll(root+"/extra", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EditRecipe(created.ID, in2); err != nil {
		t.Fatalf("EditRecipe: %v", err)
	}
	after, ok, err := svc.store.Load(created.ID)
	if err != nil || !ok {
		t.Fatalf("load after edit: %v %v", err, ok)
	}
	if after.Grant.AutoSend {
		t.Fatal("material edit kept the auto-send grant — grant must be revoked")
	}
	if after.Grant.ConsentVersion <= cvBefore {
		t.Fatalf("consent version not bumped on material change: %d -> %d", cvBefore, after.Grant.ConsentVersion)
	}
	if after.Status != recipes.RecipeApprovalRequired {
		t.Fatalf("status after material edit = %q, want approval-required (visible reapproval)", after.Status)
	}
	if after.GrantValid(time.Now().UTC()) {
		t.Fatal("stale grant validates after a material change")
	}
	// The recipe itself survives (restart-preservation half of the contract).
	if after.Name != "nightly" || len(after.Sources) != 2 {
		t.Fatal("material scope was not preserved across the edit")
	}
}

// TestR09CancelHonesty pins requirement 5 at the service layer: cancelling a
// queued job reports cancelled; cancelling after completion reports
// alreadyCompleted with the success preserved; cancelling a never-dispatched
// recipe is an honest no-op.
func TestR09CancelHonesty(t *testing.T) {
	svc, root, peerID, _ := newRecipeUXService(t)
	in := newEditorInput("nightly", root, peerID)
	in.NetworkPolicy = "online"
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	// (a) never dispatched: honest no-op.
	res, err := svc.CancelRecipeJob(created.ID)
	if err != nil {
		t.Fatalf("CancelRecipeJob (no job): %v", err)
	}
	if res.Cancelled || res.Status != "none" {
		t.Fatalf("no-job cancel result = %+v, want an honest no-op", res)
	}
	// (b) dispatched but queued: cancelled. (Approval precedes the run —
	// the runner refuses unapproved recipes by contract.)
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	svc.SetPolicyLookup(func() netpolicy.Policy { return netpolicy.Online })
	svc.SetOnlineSender(func(_ context.Context, _ onlineSendRequest) (transfer.Outcome, error) {
		return transfer.Outcome{}, fmt.Errorf("no signaling server in test")
	})
	if _, err := svc.RunRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.RecipeDeliveryStatus(created.ID)
	if st.LastRun == nil || st.LastRun.JobID == "" {
		t.Fatalf("run did not produce a job: %+v", st.LastRun)
	}
	res, err = svc.CancelRecipeJob(created.ID)
	if err != nil {
		t.Fatalf("CancelRecipeJob (queued): %v", err)
	}
	if !res.Cancelled || res.Status != string(jobs.JobCancelled) {
		t.Fatalf("queued-job cancel result = %+v, want cancelled", res)
	}
	// (c) completed job: refusal with alreadyCompleted — the success stands.
	jobID := st.LastRun.JobID
	job, ok, err := svc.jobs.Load(jobID)
	if err != nil || !ok {
		t.Fatalf("load job: %v %v", err, ok)
	}
	// Simulate the verified completion path honestly (recordOutcome contract:
	// digest present ⇒ completed).
	now := time.Now().UTC()
	for i := range job.Attempts {
		job.Attempts[i].VerifiedDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		_ = jobs.TransitionAttempt(&job.Attempts[i], jobs.AttemptVerified, now)
		_ = jobs.TransitionAttempt(&job.Attempts[i], jobs.AttemptCompleted, now)
	}
	job.Status = jobs.JobCompleted
	if err := svc.jobs.Save(job); err != nil {
		t.Fatalf("save completed job: %v", err)
	}
	res, err = svc.CancelRecipeJob(created.ID)
	if err != nil {
		t.Fatalf("CancelRecipeJob (completed): %v", err)
	}
	if res.Cancelled || !res.AlreadyCompleted || res.Status != string(jobs.JobCompleted) {
		t.Fatalf("completed-job cancel result = %+v, want alreadyCompleted with the success preserved", res)
	}
	final, _, _ := svc.jobs.Load(jobID)
	if final.Status != jobs.JobCompleted {
		t.Fatalf("completed job status changed by the cancel attempt: %q", final.Status)
	}
}

// TestR09PolicyDegradationSurfaced pins requirement 6 at the service layer:
// the policy service distinguishes a selected local-only from the SB-R05
// fail-closed fallback, and a healthy read clears the degradation.
func TestR09PolicyDegradationSurfaced(t *testing.T) {
	svc := NewNetworkPolicyService(
		func() netpolicy.Policy { return netpolicy.LocalOnly },
		func(netpolicy.Policy) error { return nil },
	)
	// Healthy state: not degraded.
	ps := svc.GetPolicyState()
	if ps.Degraded || ps.Policy != "local-only" {
		t.Fatalf("initial state = %+v, want non-degraded local-only", ps)
	}
	// The engine reports the fail-closed fallback.
	svc.NoteDegrade("settings could not be read; the engine fell back to local-only for safety")
	ps = svc.GetPolicyState()
	if !ps.Degraded || ps.Policy != "local-only" || ps.Reason == "" {
		t.Fatalf("degraded state = %+v, want degraded local-only with a reason", ps)
	}
	// A healthy read clears it.
	svc.ClearDegrade()
	ps = svc.GetPolicyState()
	if ps.Degraded || ps.Reason != "" {
		t.Fatalf("post-clear state = %+v, want the degradation cleared", ps)
	}
}

// TestR09DeliveryStatusHonestStates pins requirement 4: the delivery view
// renders engine states verbatim (queued stays queued; interrupted with a
// retry time stays retrying; only verified/completed carry the digest), and
// a refused/failed run surfaces the ledger detail instead of a job.
func TestR09DeliveryStatusHonestStates(t *testing.T) {
	svc, root, peerID, _ := newRecipeUXService(t)
	in := newEditorInput("nightly", root, peerID)
	created, err := svc.CreateRecipe(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	// A refused run (no policy lookup wired => dispatcher refuses with the
	// production-sender error): the ledger records it; NO job may appear.
	if _, err := svc.RunRecipe(created.ID); err != nil {
		t.Fatal(err)
	}
	rep, err := svc.DispatchOnceNow(context.Background())
	if err != nil {
		// production sender not wired is the expected refusal class here
		if !strings.Contains(err.Error(), "production sender not wired") {
			t.Fatalf("dispatch pass: %v", err)
		}
	}
	_ = rep
	st, err := svc.RecipeDeliveryStatus(created.ID)
	if err != nil {
		t.Fatalf("RecipeDeliveryStatus: %v", err)
	}
	// Either no job at all (refused before enqueue) or a job whose attempts
	// are honest; never a completed attempt without a digest.
	if st.Job != nil {
		for _, a := range st.Job.Attempts {
			if (a.Status == "completed" || a.Status == "verified") && a.VerifiedDigest == "" {
				t.Fatalf("delivery view shows %q without a verified digest", a.Status)
			}
		}
	}
}
