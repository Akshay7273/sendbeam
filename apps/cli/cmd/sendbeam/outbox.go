package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sendbeam/engine/jobs"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/engine/transfercenter"
	"github.com/sendbeam/wire"
)

// runOutbox implements `sendbeam outbox <subcommand>`: the offline queue for
// targeted sends. Enqueue files for trusted devices now; dispatch retries
// them with bounded backoff until they deliver, expire, or are cancelled.
func runOutbox(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		outboxUsage(stderr)
		return 2
	}
	switch args[0] {
	case "enqueue":
		return runOutboxEnqueue(args[1:], stdout, stderr)
	case "list":
		return runOutboxList(args[1:], stdout, stderr)
	case "show":
		return runOutboxShow(args[1:], stdout, stderr)
	case "dispatch":
		return runOutboxDispatch(args[1:], stdout, stderr)
	case "cancel":
		return runOutboxCancel(args[1:], stdout, stderr)
	case "retry":
		return runOutboxRetry(args[1:], stdout, stderr)
	case "prune":
		return runOutboxPrune(args[1:], stdout, stderr)
	case "forget":
		return runOutboxForget(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		outboxUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox: unknown subcommand %q\n\n", args[0])
		outboxUsage(stderr)
		return 2
	}
}

func outboxUsage(w io.Writer) {
	s := newStyleFromWriter(w)
	_, _ = fmt.Fprintln(w, s.bold("sendbeam outbox")+" — offline queue for targeted sends")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox enqueue")+" <file-or-folder>... --to @device [--to @device...] [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox list")+" [--state queued|active|interrupted|verified|completed|failed|cancelled|paused|draft|broken|all] [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox show")+" <job-id> [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox dispatch")+" [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox cancel")+" <job-id>")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox retry")+" <job-id> [@device...]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox prune")+" [--older-than 720h] [--dry-run] [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox forget")+" <job-id>")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Enqueue stores the job durably and returns immediately. Dispatch runs one")
	_, _ = fmt.Fprintln(w, "pass over due attempts: offline or busy recipients are retried later with")
	_, _ = fmt.Fprintln(w, "exponential backoff until attempts run out, the job expires, or you cancel it.")
	_, _ = fmt.Fprintln(w, "Prune enforces history retention on terminal jobs only; forget deletes one")
	_, _ = fmt.Fprintln(w, "terminal job's history explicitly. Neither ever touches live work.")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Network policies (V21-PR07):")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("--network-policy")+" binds each job at enqueue: online (default),")
	_, _ = fmt.Fprintln(w, "  prefer-local, or local-only. Dispatch reads the effective policy for")
	_, _ = fmt.Fprintln(w, "  the pass (--network-policy flag, else the configured policy) and holds")
	_, _ = fmt.Fprintln(w, "  jobs it cannot serve: a local-only job never sends online, and an online")
	_, _ = fmt.Fprintln(w, "  job never sends over a local-only dispatcher. Local-only dispatch needs")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("--peer-addr <ip:port>")+" for the trusted peer's local endpoint.")
}

// openOutboxStore opens the jobs store backing the outbox. With --config-dir
// the store lives under that directory (fully isolated); otherwise it uses
// the shared jobs dir (SENDBEAM_JOBS_DIR or the user config dir).
func openOutboxStore(configDir string) (*jobs.JobStore, error) {
	if configDir != "" {
		return jobs.OpenJobStore(filepath.Join(configDir, "jobs"))
	}
	dir, err := jobs.JobStoreDir()
	if err != nil {
		return nil, err
	}
	return jobs.OpenJobStore(dir)
}

// resolveOutboxRecipients maps --to queries to recipient refs at enqueue
// time. Trust is resolved again at dispatch, so a device revoked after
// enqueue still fails closed when its attempt runs.
func resolveOutboxRecipients(ctx context.Context, env *CLIEnvironment, to []string) ([]outbox.RecipientRef, error) {
	var refs []outbox.RecipientRef
	for _, q := range to {
		dev, err := ResolveDevice(ctx, env.TrustStore, q)
		if err != nil {
			return nil, err
		}
		if dev.Revoked || (env.Tombstones != nil && env.Tombstones.HasTombstone(ctx, dev.DeviceID)) {
			return nil, fmt.Errorf("trust for device %q is revoked", dev.LocalLabel)
		}
		refs = append(refs, outbox.RecipientRef{DeviceID: dev.DeviceID, Label: dev.LocalLabel})
	}
	return refs, nil
}

func runOutboxEnqueue(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox enqueue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var to stringList
	fs.Var(&to, "to", "target device (@name, device id, or fingerprint); repeat for more")
	defPolicy := jobs.DefaultRetryPolicy()
	maxAttempts := fs.Int("max-attempts", defPolicy.MaxAttempts, "attempts per recipient before the job fails")
	baseBackoff := fs.Duration("base-backoff", defPolicy.BaseBackoff, "initial backoff after an offline recipient")
	maxBackoff := fs.Duration("max-backoff", defPolicy.MaxBackoff, "upper bound for backoff between attempts")
	expireIn := fs.Duration("expire-in", 0, "drop the job after this long without delivery (0 = never)")
	networkPolicyFlag := fs.String("network-policy", "", "bind the job to a network policy: online, prefer-local, local-only (default online)")
	jsonOutput := fs.Bool("json", false, "print the enqueued job as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)

	if len(positionals) == 0 || len(to) == 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam outbox enqueue: need at least one file and one --to @device")
		fs.Usage()
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox enqueue: %v\n", err)
		return 1
	}
	recipients, err := resolveOutboxRecipients(ctx, env, to)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox enqueue: %v\n", err)
		return 1
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox enqueue: %v\n", err)
		return 1
	}
	policy := jobs.RetryPolicy{
		MaxAttempts: *maxAttempts,
		BaseBackoff: *baseBackoff,
		MaxBackoff:  *maxBackoff,
	}
	if *expireIn > 0 {
		policy.ExpiresAt = time.Now().UTC().Add(*expireIn)
	}
	ob := outbox.New(store, nil)
	np, err := netpolicy.Parse(*networkPolicyFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox enqueue: %v\n", err)
		return 2
	}
	job, err := ob.Enqueue(ctx, positionals, recipients, policy, np)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox enqueue: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(jobSummary(job))
		return 0
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s queued %s for %d recipient(s)\n",
		s.green("Queued"), s.cyan(shortJobID(job.JobID)), len(recipients))
	_, _ = fmt.Fprintf(stdout, "  %d file(s), %s; network policy: %s. Run %s to send due attempts.\n",
		len(job.Files), humanBytes(job.TotalSize), job.EffectiveNetworkPolicy(), s.cyan("sendbeam outbox dispatch"))
	return 0
}

func runOutboxList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print jobs as JSON")
	stateFilter := fs.String("state", "all", "only show jobs in this transfer-center state")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox list: %v\n", err)
		return 1
	}
	center := transfercenter.New(store, outbox.New(store, nil))
	snap, err := center.Snapshot()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snap)
		return 0
	}
	s := newStyleFromWriter(stdout)
	if snap.Summary.Total == 0 {
		_, _ = fmt.Fprintln(stdout, "No queued jobs.")
		return 0
	}
	want := transfercenter.DisplayState(strings.ToLower(*stateFilter))
	if want != "all" {
		known := false
		for _, g := range snap.Groups {
			if g.State == want {
				known = true
			}
		}
		if !known {
			_, _ = fmt.Fprintf(stderr, "sendbeam outbox list: unknown state %q\n", *stateFilter)
			return 2
		}
	}
	shown := 0
	for _, g := range snap.Groups {
		if want != "all" && g.State != want {
			continue
		}
		if len(g.Jobs) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", s.bold("== "+string(g.State)+" =="))
		for _, j := range g.Jobs {
			if j.State == transfercenter.StateBroken {
				_, _ = fmt.Fprintf(stdout, "%s  %s\n", s.red("BROKEN"), shortJobID(j.JobID))
				shown++
				continue
			}
			_, _ = fmt.Fprintf(stdout, "%s  %-8s %d file(s) %s  %d/%d/%d done/failed/total recipients  [%s]\n",
				s.cyan(shortJobID(j.JobID)), string(j.State),
				j.Files, humanBytes(j.TotalSize), j.Delivered, j.Failed, j.Recipients, j.NetworkPolicy)
			shown++
		}
	}
	if shown == 0 {
		_, _ = fmt.Fprintf(stdout, "No jobs in state %q.\n", *stateFilter)
	}
	return 0
}

func runOutboxShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the job as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam outbox show: need exactly one <job-id>")
		fs.Usage()
		return 2
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox show: %v\n", err)
		return 1
	}
	center := transfercenter.New(store, outbox.New(store, nil))
	detail, err := center.Get(positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox show: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(detail)
		return 0
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s  %s\n", s.bold("Job"), s.cyan(detail.JobID))
	_, _ = fmt.Fprintf(stdout, "  state:      %s\n", detail.State)
	_, _ = fmt.Fprintf(stdout, "  files:      %d (%s)\n", detail.Files, humanBytes(detail.TotalSize))
	_, _ = fmt.Fprintf(stdout, "  created:    %s\n", detail.CreatedAt.Local().Format(time.RFC3339))
	if detail.ExpiresAt != nil {
		_, _ = fmt.Fprintf(stdout, "  expires:    %s\n", detail.ExpiresAt.Local().Format(time.RFC3339))
	}
	if detail.LastError != "" {
		_, _ = fmt.Fprintf(stdout, "  last error: %s\n", detail.LastError)
	}
	if detail.NextRetryAt != nil && detail.NextRetryAt.After(time.Now()) {
		_, _ = fmt.Fprintf(stdout, "  next retry: %s\n", detail.NextRetryAt.Local().Format(time.Kitchen))
	}
	_, _ = fmt.Fprintf(stdout, "  recipients: %d (%d delivered, %d failed)\n", detail.Recipients, detail.Delivered, detail.Failed)
	for _, a := range detail.Attempts {
		line := fmt.Sprintf("    %s (%s): %s, %d/%d attempts",
			a.Label, shortJobID(a.DeviceID), a.State, a.Attempts, a.MaxAttempts)
		if a.LastError != "" {
			line += " — " + a.LastError
		}
		if a.State == transfercenter.StateQueued && a.NextRetryAt != nil && a.NextRetryAt.After(time.Now()) {
			line += " (retry at " + a.NextRetryAt.Local().Format(time.Kitchen) + ")"
		}
		_, _ = fmt.Fprintln(stdout, line)
	}
	return 0
}

func runOutboxDispatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox dispatch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (development only)")
	relayOnly := fs.Bool("relay-only", false, "force relayed transport")
	var iceServer iceServerList
	fs.Var(&iceServer, "ice-server", "ICE server URL (repeatable)")
	privateMode := fs.Bool("private", false, "hide file names and sizes from the relay")
	requirePadding := fs.Bool("require-padding", false, "pad the transfer to hide its true size")
	jitter := fs.Duration("jitter", 0, "random delay before relay registration (e.g. 500ms)")
	timeout := fs.Duration("timeout", 0, "per-recipient transfer timeout (0 = none)")
	concurrency := fs.Int("concurrency", 4, "parallel recipient transfers")
	jsonOutput := fs.Bool("json", false, "print the dispatch report as JSON")
	networkPolicyFlag := fs.String("network-policy", "", "effective network policy for this dispatch pass: online, prefer-local, local-only (default: configured policy)")
	peerAddr := fs.String("peer-addr", "", "manual local peer endpoint <ip:port> for local-only dispatch")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	effective, err := resolveNetworkPolicy(*networkPolicyFlag, *configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %v\n", err)
		return 2
	}

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %v\n", err)
		return 1
	}
	localID, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: identity error: %v\n", err)
		return 1
	}
	ice, err := iceServers(iceServer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %s\n", err)
		return 2
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %v\n", err)
		return 1
	}
	dialWriter := io.Discard
	if !*jsonOutput {
		dialWriter = stderr
	}
	cfg := targetSendConfig{
		server:         *server,
		insecure:       *insecure,
		relayOnly:      *relayOnly,
		ice:            ice,
		privateMode:    *privateMode,
		requirePadding: *requirePadding,
		jitter:         *jitter,
		dialWriter:     dialWriter,
	}
	concurrencyLimit := *concurrency
	if concurrencyLimit < 1 {
		concurrencyLimit = 1
	}
	perTarget := *timeout
	sender := func(ctx context.Context, job jobs.Job, attempt jobs.RecipientAttempt, paths []string) outbox.SendOutcome {
		// V21-PR07 per-job route binding (second line of defense after
		// the outbox dispatch gate):
		// - a local-only job is dispatched through the offline sender
		//   only, never the online one;
		// - a prefer-local job tries the approved local route first when
		//   a manual local endpoint is configured, then falls back to
		//   the online sender explicitly (the fallback is visible in the
		//   attempt error/output, not silent).
		switch job.EffectiveNetworkPolicy() {
		case netpolicy.LocalOnly:
			return outboxLocalSend(ctx, env, job, attempt, paths, netpolicy.LocalOnly, effective, *peerAddr, *requirePadding, *privateMode)
		case netpolicy.PreferLocal:
			if effective == netpolicy.PreferLocal && *peerAddr != "" {
				out := outboxLocalSend(ctx, env, job, attempt, paths, netpolicy.PreferLocal, effective, *peerAddr, *requirePadding, *privateMode)
				if out.Status == transfer.StatusOk {
					return out
				}
				localErr := out.Error
				fb := outboxTargetSend(ctx, env, localID, attempt, paths, cfg, perTarget)
				if fb.Status == transfer.StatusOk {
					_, _ = fmt.Fprintf(stderr, "job %s: local route failed (%s); fell back to online\n", shortJobID(job.JobID), localErr)
				} else if fb.Error != "" {
					fb.Error = "local route: " + localErr + "; online fallback: " + fb.Error
				} else {
					fb.Error = "local route: " + localErr + "; online fallback: " + string(fb.Status)
				}
				return fb
			}
		}
		return outboxTargetSend(ctx, env, localID, attempt, paths, cfg, perTarget)
	}
	ob := outbox.New(store, sender)
	rep, err := ob.DispatchOnce(ctx, outbox.DispatchOptions{Concurrency: concurrencyLimit, LeaseTTL: jobs.DefaultLeaseTTL, EffectivePolicy: effective})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %v\n", err)
		return 1
	}
	if !*jsonOutput {
		_, _ = fmt.Fprintf(stderr, "dispatching under network policy: %s\n", effective)
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}
	s := newStyleFromWriter(stdout)
	if len(rep.Results) == 0 && len(rep.Skipped) == 0 {
		_, _ = fmt.Fprintln(stdout, "Nothing due: no queued attempts ready to send.")
		return 0
	}
	for _, r := range rep.Results {
		label := s.green("delivered")
		if r.Outcome != transfer.StatusOk {
			label = s.red(string(r.Outcome))
		}
		_, _ = fmt.Fprintf(stdout, "%s  %s -> %s (%s)\n",
			label, shortJobID(r.JobID), r.Label, shortJobID(r.DeviceID))
		if r.Error != "" {
			_, _ = fmt.Fprintf(stdout, "    %s\n", r.Error)
		}
	}
	for _, sk := range rep.Skipped {
		_, _ = fmt.Fprintf(stdout, "%s  %s\n", s.yellow("skipped"), sk)
	}
	// Like `send --to`: a pass that terminally failed an attempt exits
	// non-zero. Attempts merely waiting for backoff are not failures.
	for _, r := range rep.Results {
		if r.To == jobs.AttemptFailed {
			return 1
		}
	}
	return 0
}

// outboxTargetSend is the production outbox sender: one targeted transfer to
// the trusted device recorded on the attempt. Trust credentials resolve here,
// at dispatch time, and the resolved device ID must equal the attempt's
// device ID — the job file's label is never trusted for peer binding.
func outboxTargetSend(ctx context.Context, env *CLIEnvironment, localID *wire.DeviceIdentity, attempt jobs.RecipientAttempt, paths []string, cfg targetSendConfig, perTarget time.Duration) outbox.SendOutcome {
	fail := func(format string, args ...any) outbox.SendOutcome {
		return outbox.SendOutcome{Status: transfer.StatusFailed, Error: fmt.Sprintf(format, args...)}
	}
	resolved, err := resolveSendTargets(ctx, env, []string{attempt.DeviceID})
	if err != nil {
		return fail("resolve recipient: %v", err)
	}
	if !strings.EqualFold(resolved[0].record.DeviceID, attempt.DeviceID) {
		return fail("trust record mismatch: %q resolved to a different device; refusing to send", attempt.DeviceID)
	}
	sources, _, err := transfer.NewOSFileSources(paths)
	if err != nil {
		return fail("read sources: %v", err)
	}
	targets := buildBroadcastTargets(env, localID, resolved, sources, cfg)
	var transferred int64
	tctx := ctx
	cancel := context.CancelFunc(func() {})
	if perTarget > 0 {
		tctx, cancel = context.WithTimeout(ctx, perTarget)
	}
	defer cancel()
	res := transfer.RunBroadcast(tctx, targets, transfer.BroadcastOptions{
		Concurrency:   1,
		TargetTimeout: perTarget,
		OnTargetProgress: func(_ string, bytes int64) {
			transferred = bytes
		},
	})
	if len(res.Results) == 0 {
		return fail("transfer produced no result")
	}
	r := res.Results[0]
	return outbox.SendOutcome{
		Status:           r.Status,
		Error:            r.Error,
		Digest:           r.Digest,
		BytesTransferred: transferred,
	}
}

func runOutboxCancel(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox cancel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam outbox cancel: need exactly one <job-id>")
		fs.Usage()
		return 2
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox cancel: %v\n", err)
		return 1
	}
	ob := outbox.New(store, nil)
	if err := ob.Cancel(positionals[0]); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox cancel: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s %s\n", s.yellow("Cancelled"), s.cyan(shortJobID(positionals[0])))
	return 0
}

func runOutboxRetry(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox retry", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var to stringList
	fs.Var(&to, "to", "only retry these devices (@name or device id); default: all failed")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam outbox retry: need exactly one <job-id>")
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var deviceIDs []string
	if len(to) > 0 {
		env, err := InitCLIEnvironment(*configDir)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam outbox retry: %v\n", err)
			return 1
		}
		for _, q := range to {
			dev, err := ResolveDevice(ctx, env.TrustStore, q)
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "sendbeam outbox retry: %v\n", err)
				return 1
			}
			deviceIDs = append(deviceIDs, dev.DeviceID)
		}
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox retry: %v\n", err)
		return 1
	}
	ob := outbox.New(store, nil)
	n, err := ob.RetryFailed(positionals[0], deviceIDs)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox retry: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s %d recipient(s) on %s; run %s to send.\n",
		s.green("Re-queued"), n, s.cyan(shortJobID(positionals[0])), s.cyan("sendbeam outbox dispatch"))
	return 0
}

// runOutboxPrune implements `sendbeam outbox prune`: explicit history
// retention. Only terminal jobs older than the retention window are removed;
// live, leased, and unreadable jobs are never touched.
func runOutboxPrune(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	olderThan := fs.Duration("older-than", 0, "override retention for all terminal classes (default: 30d completed/failed, 7d cancelled)")
	dryRun := fs.Bool("dry-run", false, "list what would be pruned without deleting")
	jsonOutput := fs.Bool("json", false, "print the prune report as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox prune: %v\n", err)
		return 1
	}
	policy := transfercenter.DefaultRetentionPolicy()
	if *olderThan > 0 {
		policy = transfercenter.RetentionPolicy{
			CompletedFor: *olderThan,
			FailedFor:    *olderThan,
			CancelledFor: *olderThan,
		}
	}
	center := transfercenter.New(store, outbox.New(store, nil))
	rep, err := center.Prune(time.Now().UTC(), policy, *dryRun)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox prune: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}
	s := newStyleFromWriter(stdout)
	if *dryRun {
		_, _ = fmt.Fprintln(stdout, s.bold("Dry run — nothing deleted."))
	}
	if len(rep.Pruned) == 0 {
		_, _ = fmt.Fprintln(stdout, "Nothing to prune: no terminal jobs past retention.")
		return 0
	}
	for _, id := range rep.Pruned {
		_, _ = fmt.Fprintf(stdout, "%s %s\n", s.yellow("Pruned"), s.cyan(shortJobID(id)))
	}
	return 0
}

// runOutboxForget implements `sendbeam outbox forget`: delete one terminal
// job's history explicitly. Live jobs are refused — cancel first.
func runOutboxForget(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam outbox forget: need exactly one <job-id>")
		fs.Usage()
		return 2
	}
	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox forget: %v\n", err)
		return 1
	}
	center := transfercenter.New(store, outbox.New(store, nil))
	if err := center.Forget(positionals[0]); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox forget: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s %s\n", s.yellow("Forgot"), s.cyan(shortJobID(positionals[0])))
	return 0
}

// jobSummary is the JSON shape for `outbox enqueue/show --json`.
type jobSummaryJSON struct {
	JobID         string                 `json:"job_id"`
	Status        string                 `json:"status"`
	NetworkPolicy string                 `json:"network_policy"`
	Files         int                    `json:"files"`
	TotalBytes    int64                  `json:"total_bytes"`
	Recipients    []recipientSummaryJSON `json:"recipients"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
}

type recipientSummaryJSON struct {
	DeviceID  string `json:"device_id"`
	Label     string `json:"label"`
	Status    string `json:"status"`
	Attempts  int    `json:"attempts"`
	LastError string `json:"last_error,omitempty"`
}

func jobSummary(job jobs.Job) jobSummaryJSON {
	sum := jobSummaryJSON{
		JobID:         job.JobID,
		Status:        string(job.Status),
		NetworkPolicy: job.EffectiveNetworkPolicy().String(),
		Files:         len(job.Files),
		TotalBytes:    job.TotalSize,
		CreatedAt:     job.CreatedAt,
	}
	if !job.Policy.ExpiresAt.IsZero() {
		t := job.Policy.ExpiresAt
		sum.ExpiresAt = &t
	}
	for _, a := range job.Attempts {
		sum.Recipients = append(sum.Recipients, recipientSummaryJSON{
			DeviceID:  a.DeviceID,
			Label:     a.Label,
			Status:    string(a.Status),
			Attempts:  a.Attempts,
			LastError: a.LastError,
		})
	}
	return sum
}

func shortJobID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
