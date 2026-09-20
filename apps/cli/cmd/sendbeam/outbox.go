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
	"github.com/sendbeam/engine/outbox"
	"github.com/sendbeam/engine/transfer"
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
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox list")+" [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox show")+" <job-id> [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox dispatch")+" [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox cancel")+" <job-id>")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam outbox retry")+" <job-id> [@device...]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Enqueue stores the job durably and returns immediately. Dispatch runs one")
	_, _ = fmt.Fprintln(w, "pass over due attempts: offline or busy recipients are retried later with")
	_, _ = fmt.Fprintln(w, "exponential backoff until attempts run out, the job expires, or you cancel it.")
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
	job, err := ob.Enqueue(ctx, positionals, recipients, policy)
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
	_, _ = fmt.Fprintf(stdout, "  %d file(s), %s. Run %s to send due attempts.\n",
		len(job.Files), humanBytes(job.TotalSize), s.cyan("sendbeam outbox dispatch"))
	return 0
}

func runOutboxList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("outbox list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print jobs as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	store, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox list: %v\n", err)
		return 1
	}
	entries, err := store.List()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox list: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(entries)
		return 0
	}
	s := newStyleFromWriter(stdout)
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(stdout, "No queued jobs.")
		return 0
	}
	for _, e := range entries {
		if !e.JobOK {
			_, _ = fmt.Fprintf(stdout, "%s  %s\n", s.red("BROKEN"), shortJobID(e.JobID))
			continue
		}
		_, _ = fmt.Fprintf(stdout, "%s  %-8s %d file(s) %s  %d/%d/%d done/failed/total recipients\n",
			s.cyan(shortJobID(e.JobID)), outboxStatusLabel(e.Status),
			e.Files, humanBytes(e.TotalSize), e.Completed, e.Failed, e.Recipients)
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
	ob := outbox.New(store, nil)
	job, ok, err := ob.Get(positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox show: %v\n", err)
		return 1
	}
	if !ok {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox show: no job %q\n", positionals[0])
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(jobSummary(job))
		return 0
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s  %s\n", s.bold("Job"), s.cyan(job.JobID))
	_, _ = fmt.Fprintf(stdout, "  status:     %s\n", outboxStatusLabel(job.Status))
	_, _ = fmt.Fprintf(stdout, "  files:      %d (%s)\n", len(job.Files), humanBytes(job.TotalSize))
	_, _ = fmt.Fprintf(stdout, "  created:    %s\n", job.CreatedAt.Local().Format(time.RFC3339))
	if !job.Policy.ExpiresAt.IsZero() {
		_, _ = fmt.Fprintf(stdout, "  expires:    %s\n", job.Policy.ExpiresAt.Local().Format(time.RFC3339))
	}
	_, _ = fmt.Fprintf(stdout, "  recipients: %d\n", len(job.Attempts))
	for _, a := range job.Attempts {
		line := fmt.Sprintf("    %s (%s): %s, %d/%d attempts",
			a.Label, shortJobID(a.DeviceID), attemptStatusLabel(a.Status), a.Attempts, job.Policy.MaxAttempts)
		if a.Status == jobs.AttemptFailed && a.LastError != "" {
			line += " — " + a.LastError
		}
		if a.Status == jobs.AttemptQueued && !a.NextRetryAt.IsZero() && a.NextRetryAt.After(time.Now()) {
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
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	sender := func(ctx context.Context, _ jobs.Job, attempt jobs.RecipientAttempt, paths []string) outbox.SendOutcome {
		return outboxTargetSend(ctx, env, localID, attempt, paths, cfg, perTarget)
	}
	ob := outbox.New(store, sender)
	rep, err := ob.DispatchOnce(ctx, outbox.DispatchOptions{Concurrency: concurrencyLimit, LeaseTTL: jobs.DefaultLeaseTTL})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam outbox dispatch: %v\n", err)
		return 1
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

// jobSummary is the JSON shape for `outbox enqueue/show --json`.
type jobSummaryJSON struct {
	JobID      string                 `json:"job_id"`
	Status     string                 `json:"status"`
	Files      int                    `json:"files"`
	TotalBytes int64                  `json:"total_bytes"`
	Recipients []recipientSummaryJSON `json:"recipients"`
	ExpiresAt  *time.Time             `json:"expires_at,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
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
		JobID:      job.JobID,
		Status:     string(job.Status),
		Files:      len(job.Files),
		TotalBytes: job.TotalSize,
		CreatedAt:  job.CreatedAt,
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

func outboxStatusLabel(st jobs.JobStatus) string {
	switch st {
	case jobs.JobQueued:
		return "queued"
	case jobs.JobDispatching:
		return "sending"
	case jobs.JobPaused:
		return "paused"
	case jobs.JobCompleted:
		return "done"
	case jobs.JobFailed:
		return "failed"
	case jobs.JobCancelled:
		return "cancelled"
	default:
		return string(st)
	}
}

func attemptStatusLabel(st jobs.AttemptStatus) string {
	switch st {
	case jobs.AttemptQueued:
		return "queued"
	case jobs.AttemptActive:
		return "sending"
	case jobs.AttemptInterrupted:
		return "interrupted"
	case jobs.AttemptVerified:
		return "verified"
	case jobs.AttemptCompleted:
		return "delivered"
	case jobs.AttemptFailed:
		return "failed"
	default:
		return string(st)
	}
}
