// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

// localSendResult is the outcome of one offline device send.
type localSendResult struct {
	Outcome  *transfer.Outcome
	Endpoint string // validated peer endpoint host:port
	DeviceID string
	Label    string
}

// localSendParams carries the caller-controlled options for one offline
// device send.
type localSendParams struct {
	// Policy is the caller's effective network policy; must be LocalOnly.
	Policy netpolicy.Policy
	// PeerAddr is the manually validated peer endpoint (ip:port).
	PeerAddr string
	// RequirePadding / PrivateMode are passed straight to the engine.
	RequirePadding bool
	PrivateMode    bool
	// Resume carries an explicit cross-session resume context (built by
	// the caller from the sender record); nil sends fresh.
	Resume *transfer.ResumeContext
	// OnResume reports the engine's resume decision for UX; may be nil.
	OnResume func(transfer.ResumeResult)
	// OnTransport reports the selected byte path; OnProgress reports
	// cumulative verified bytes. Both may be nil.
	OnTransport func(string)
	OnProgress  func(int64)
}

// runLocalTransferToDevice is the shared offline send core used by the
// one-shot `send --network-policy=local-only` path and the outbox local
// dispatcher (V21-PR07). It enforces, in order: the caller's effective
// policy must be local-only (defense in depth — a local-only send must
// never silently become an online send); the peer must be a trusted,
// non-revoked paired device; the endpoint must validate against the
// interface-derived route policy; and the transfer runs through
// packages/engine/localtransfer with no public signaling, STUN/TURN,
// relay, or updater contacted at any step.
func runLocalTransferToDevice(ctx context.Context, env *CLIEnvironment, filePaths []string, toDevice string, params localSendParams) (*localSendResult, error) {
	fail := func(format string, args ...any) (*localSendResult, error) {
		return nil, fmt.Errorf(format, args...)
	}
	if params.Policy != netpolicy.LocalOnly {
		return fail("local-only send requires the local-only network policy (refusing to fall back to online)")
	}
	if len(filePaths) == 0 {
		return fail("a file to send is required")
	}
	if toDevice == "" {
		return fail("local-only send requires a trusted target device (no invite codes offline)")
	}
	if params.PeerAddr == "" {
		return fail("local-only send requires --peer-addr <ip:port>")
	}

	// Trust gate: resolveSendTargets rejects unknown or revoked devices and
	// resolves the pair secret. Unknown devices fail closed here.
	resolved, err := resolveSendTargets(ctx, env, []string{toDevice})
	if err != nil {
		return fail("%v", err)
	}
	rec := resolved[0]

	identity, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		return fail("identity: %v", err)
	}

	// Route gate: the endpoint is validated against the interface-derived
	// route policy. Non-local addresses (e.g. a public IP) are rejected.
	// RoutePolicy review (V21-PR07): AllowLoopback stays true. Loopback
	// can never cause public egress — the invariant the local path
	// protects — and the peer is still trust-gated (paired, non-revoked)
	// and Opaque-authenticated before any bytes move. It is needed for
	// same-host operation (sender and receiver on one machine), which is
	// also how the local path is exercised in tests.
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	endpoint, err := tab.AddManual(rec.record.DeviceID, params.PeerAddr)
	if err != nil {
		return fail("--peer-addr %q rejected: %v", params.PeerAddr, err)
	}

	sources, _, err := transfer.NewOSFileSources(filePaths)
	if err != nil {
		return fail("%v", err)
	}

	// Sender record (V21-PR07): the same durable resume contract as the
	// online path. PrepareSender returns the stable transfer id for this
	// source set (reused across retries so an interrupted send keeps its
	// identity), the manifest hook that creates/verifies the record, and
	// whether a record already exists. A changed source set fails here —
	// before any bytes move — instead of sending under a stale id.
	//
	// Identity review (V21-PR07): the record is keyed by source paths, so
	// the same files sent to different devices share one transfer id.
	// This is safe because the record holds no per-recipient offsets (the
	// receiver tracks its own partial state), resume credentials are
	// derived per session from a fresh resume root, and every session
	// still runs the Opaque device authentication. Local sends address a
	// single --to device, so no cross-recipient state can collide.
	senderStore, err := openLocalSenderStore(env.ConfigDir)
	if err != nil {
		return fail("sender state: %v", err)
	}
	transferID, onSendManifest, reused, err := transfer.PrepareSender(senderStore, filePaths, sources)
	if err != nil {
		return fail("%v", err)
	}

	// V21-PR07: a retry reusing an interrupted record resumes with the
	// authenticated resume context decoded from that record — not merely
	// the stable id. The receiver authenticates the resume through the
	// shared contract (fresh key epoch) and skips cleanly when it holds
	// no partial state, so advertising resume is always safe.
	resumeCtx := params.Resume
	onResume := params.OnResume
	if resumeCtx == nil && reused {
		resumeCtx = resumeContextForRetry(senderStore, transferID)
		if resumeCtx != nil && onResume == nil {
			onResume = func(r transfer.ResumeResult) {
				switch {
				case r.Authenticated:
					fmt.Fprintf(os.Stderr, "authenticated resume of local transfer %s\n", transferID)
				case r.Attempted:
					fmt.Fprintf(os.Stderr, "authenticating resume for local transfer %s\n", transferID)
				case r.Skipped:
					fmt.Fprintf(os.Stderr, "receiver did not authenticate resume; sending fresh\n")
				}
			}
		}
	}

	out, err := localtransfer.Transfer(ctx, localtransfer.Options{
		Identity:     identity,
		Store:        env.TrustStore,
		Resolver:     env.Secrets,
		Table:        tab,
		PeerDeviceID: rec.record.DeviceID,
		PeerLabel:    rec.record.LocalLabel,
		Role:         rendezvous.RoleOfferer,
		Sources:      sources,
		TransferID:   transferID,
		Resume:       resumeCtx,
		OnResume:     onResume,
		// The record is created (or verified, on retry) when the
		// manifest frame goes out; the resume credential is attached
		// strictly before that frame is transmitted, so an interrupted
		// local send can later resume with authentication and fresh
		// keys through `sendbeam transfers resume <id>`.
		OnSendManifest: onSendManifest,
		OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
			return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
		},
		RequirePadding: params.RequirePadding,
		Private:        params.PrivateMode,
		OnTransport:    params.OnTransport,
		OnProgress:     params.OnProgress,
	})
	if err != nil {
		return fail("local-only transfer failed: %v", err)
	}
	return &localSendResult{Outcome: out, Endpoint: endpoint.Endpoint.HostPort, DeviceID: rec.record.DeviceID, Label: rec.record.LocalLabel}, nil
}

// openLocalSenderStore opens the sender-state store for local sends. With a
// custom config dir the state stays under it (fully isolated, like the
// outbox store); otherwise it uses the shared sender-state dir.
func openLocalSenderStore(configDir string) (*transfer.SenderStore, error) {
	if configDir != "" {
		return transfer.OpenSenderStore(filepath.Join(configDir, "sender"))
	}
	dir, err := transfer.SenderStoreDir()
	if err != nil {
		return nil, err
	}
	return transfer.OpenSenderStore(dir)
}

// outboxLocalSend is the outbox SendFunc route for local-capable jobs
// (V21-PR07): it dispatches through the offline localtransfer path, never
// the online sender. jobPolicy is the job-bound policy being served (the
// local route serves LocalOnly and PreferLocal jobs); effective is the
// dispatcher's policy for this pass. Defense in depth: it re-verifies the
// route is allowed under the effective policy rather than trusting the
// outbox gate alone.
func outboxLocalSend(ctx context.Context, env *CLIEnvironment, job jobs.Job, attempt jobs.RecipientAttempt, paths []string, jobPolicy, effective netpolicy.Policy, peerAddr string, requirePadding, privateMode bool) outbox.SendOutcome {
	fail := func(format string, args ...any) outbox.SendOutcome {
		return outbox.SendOutcome{Status: transfer.StatusFailed, Error: fmt.Sprintf(format, args...)}
	}
	// Defense in depth (the outbox gate checks this too): the job must be
	// satisfiable under the effective policy, and the local route must be
	// allowed under it. A local-only job under an online dispatcher, or an
	// online job reaching the local sender, both fail closed here.
	if !jobPolicy.DispatchableUnder(effective) {
		return fail("job policy %q is not satisfiable under effective policy %q; refusing to send",
			jobPolicy, effective)
	}
	if !netpolicy.LocalOnly.DispatchableUnder(effective) {
		return fail("local route not allowed under effective policy %q; refusing to send online for job %s",
			effective, shortJobID(job.JobID))
	}
	if peerAddr == "" {
		return fail("local dispatch of job %s requires --peer-addr <ip:port> (manual local endpoint)", shortJobID(job.JobID))
	}
	var sentBytes int64
	res, err := runLocalTransferToDevice(ctx, env, paths, attempt.DeviceID, localSendParams{
		Policy:         netpolicy.LocalOnly,
		PeerAddr:       peerAddr,
		RequirePadding: requirePadding,
		PrivateMode:    privateMode,
		OnProgress:     func(n int64) { sentBytes = n },
	})
	if err != nil {
		return fail("%v", err)
	}
	digest := res.Outcome.Digest
	if digest == "" {
		return fail("local transfer reported success without a content digest; not marking delivered")
	}
	return outbox.SendOutcome{Status: transfer.StatusOk, Digest: digest, BytesTransferred: sentBytes}
}

// resumeContextForRetry builds the authenticated resume context for a
// retried local send from the reused sender record (V21-PR07). It returns
// nil when there is no record, the record carries no resume secret, or the
// secret cannot be decoded — in which case the caller sends fresh.
func resumeContextForRetry(senderStore *transfer.SenderStore, transferID string) *transfer.ResumeContext {
	rec, ok, err := senderStore.Load(transferID)
	if err != nil || !ok || rec.ResumeSecret == nil {
		return nil
	}
	secret, err := wire.DecodeResumeSecretEnvelope(rec.ResumeSecret)
	if err != nil {
		return nil
	}
	return &transfer.ResumeContext{
		TransferID:          transferID,
		ManifestFingerprint: rec.ManifestFingerprint,
		Role:                wire.RoleOfferer,
		ResumeSecret:        secret,
	}
}

// runLocalOnlySend performs a genuinely offline send: the peer is a trusted
// paired device, the route is a validated local endpoint (manual --peer-addr
// or a discovered candidate), and the transfer runs through
// packages/engine/localtransfer — no public signaling server, STUN/TURN,
// relay, or updater is contacted at any step (V21-PR06).
func runLocalOnlySend(env *CLIEnvironment, filePaths []string, hp handoffPayload, toDevice, peerAddr string, requirePadding, privateMode, jsonOutput bool, policy netpolicy.Policy, stdout, stderr io.Writer) int {
	// Policy gate (defense in depth): the dispatcher only routes here when
	// the effective policy is local-only, but verify again — a local-only
	// send must never silently become an online send.
	if hp.Kind != "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: --text/--link handoffs are not supported over --network-policy=local-only in this release (files only)")
		return 2
	}

	var transport string
	var sentBytes int64
	res, err := runLocalTransferToDevice(context.Background(), env, filePaths, toDevice, localSendParams{
		Policy:         policy,
		PeerAddr:       peerAddr,
		RequirePadding: requirePadding,
		PrivateMode:    privateMode,
		OnTransport: func(t string) {
			transport = t
			if !jsonOutput {
				_, _ = fmt.Fprintf(stdout, "route: %s (local direct)\n", t)
			}
		},
		OnProgress: func(n int64) {
			sentBytes = n
			if !jsonOutput {
				_, _ = fmt.Fprintf(stderr, "\rprogress: %s", humanBytes(n))
			}
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "\nsendbeam send: %v\n", err)
		return 1
	}
	out := res.Outcome

	if jsonOutput {
		result := map[string]any{
			"status":         "sent",
			"network_policy": "local-only",
			"device_id":      res.DeviceID,
			"peer_addr":      res.Endpoint,
			"transport":      transport,
			"bytes":          sentBytes,
			"name":           out.Name,
			"size":           out.Size,
			"digest":         out.Digest,
		}
		raw, _ := json.Marshal(result)
		_, _ = fmt.Fprintln(stdout, string(raw))
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "\n")
	_, _ = fmt.Fprintf(stdout, "network policy: local-only (no public signaling, STUN/TURN, or relay contacted)\n")
	_, _ = fmt.Fprintf(stdout, "sent %s to %s (%s)\n", humanBytes(out.Size), res.Label, res.DeviceID)
	return 0
}
