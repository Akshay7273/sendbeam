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
	"github.com/sendbeam/engine/recipes"
	"github.com/sendbeam/wire"
)

// runRecipe implements `sendbeam recipe <subcommand>`: saved handoff
// recipes (V22-PR02). A recipe names explicit local sources and fixed
// trusted recipients; `preview` resolves a dry-run plan that sends
// nothing, and `run` explicitly enqueues one ordinary outbox job. Recipes
// stay useful without any daemon.
func runRecipe(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		recipeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return runRecipeList(args[1:], stdout, stderr)
	case "show":
		return runRecipeShow(args[1:], stdout, stderr)
	case "create":
		return runRecipeCreate(args[1:], stdout, stderr)
	case "edit":
		return runRecipeEdit(args[1:], stdout, stderr)
	case "duplicate":
		return runRecipeDuplicate(args[1:], stdout, stderr)
	case "delete":
		return runRecipeDelete(args[1:], stdout, stderr)
	case "approve":
		return runRecipeApprove(args[1:], stdout, stderr)
	case "grant":
		return runRecipeGrant(args[1:], stdout, stderr)
	case "revoke":
		return runRecipeRevoke(args[1:], stdout, stderr)
	case "disable":
		return runRecipeDisable(args[1:], stdout, stderr)
	case "enable":
		return runRecipeEnable(args[1:], stdout, stderr)
	case "preview":
		return runRecipePreview(args[1:], stdout, stderr)
	case "run":
		return runRecipeRun(args[1:], stdout, stderr)
	case "watch":
		return runRecipeWatch(args[1:], stdout, stderr)
	case "scheduler":
		return runRecipeScheduler(args[1:], stdout, stderr)
	case "export":
		return runRecipeExport(args[1:], stdout, stderr)
	case "import":
		return runRecipeImport(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		recipeUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe: unknown subcommand %q\n\n", args[0])
		recipeUsage(stderr)
		return 2
	}
}

func recipeUsage(w io.Writer) {
	s := newStyleFromWriter(w)
	_, _ = fmt.Fprintln(w, s.bold("sendbeam recipe")+" — saved handoff workflows (explicit one-shot runs)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe list")+" [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe show")+" <id> [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe create")+" --name NAME --source PATH [--source ...] --to DEVICE [--to ...] [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe edit")+" <id> [flags]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe duplicate")+" <id> --name NEW")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe delete")+" <id>")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe approve")+" <id>")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe grant")+" <id>      "+s.dim("(explicit auto-send consent for the routine runner)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe revoke")+" <id>     "+s.dim("(withdraw auto-send consent)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe disable")+" <id>    "+s.dim("(switch the routine off: no future dispatch of any kind)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe enable")+" <id>     "+s.dim("(re-enable to approval-required; auto-send consent revoked)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe preview")+" <id> [--json]   "+s.dim("(dry-run: sends nothing)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe run")+" <id> [--json]       "+s.dim("(explicit one-shot: enqueues one job)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe watch")+" <id>              "+s.dim("(foreground: dispatch on watched-folder changes until Ctrl+C)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe scheduler")+"              "+s.dim("(foreground: run due schedule-triggered recipes until Ctrl+C)"))
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe export")+" <id> [--out FILE]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam recipe import")+" <file>")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "New recipes start "+s.yellow("approval-required")+": preview them, then")
	_, _ = fmt.Fprintln(w, s.cyan("sendbeam recipe approve")+" <id> before the first run. preview is")
	_, _ = fmt.Fprintln(w, "always a dry-run — it never creates jobs or sends anything.")
}

// openRecipeStore opens the recipe store. With --config-dir the store lives
// under that directory (fully isolated); otherwise SENDBEAM_RECIPES_DIR or
// the user config dir is used.
func openRecipeStore(configDir string) (*recipes.RecipeStore, error) {
	if configDir != "" {
		return recipes.OpenRecipeStore(filepath.Join(configDir, "recipes"))
	}
	dir, err := recipes.RecipeStoreDir()
	if err != nil {
		return nil, err
	}
	return recipes.OpenRecipeStore(dir)
}

// loadRecipe loads one recipe by id, failing closed on corrupt records.
func loadRecipe(store *recipes.RecipeStore, id string) (recipes.Recipe, error) {
	r, ok, err := store.Load(id)
	if err != nil {
		return recipes.Recipe{}, err
	}
	if !ok {
		return recipes.Recipe{}, fmt.Errorf("no recipe %q", id)
	}
	return r, nil
}

func shortRecipeID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// resolveRecipeRecipients resolves --to queries (device id, @name, or
// fingerprint prefix) to trusted devices, using the trust record's local
// label unless a positional --label overrides it. Labels align by position
// with --to; one --label with several --to is ambiguous and rejected.
func resolveRecipeRecipients(ctx context.Context, env *CLIEnvironment, to, labels []string) ([]recipes.RecipeRecipient, error) {
	if len(labels) > 1 && len(labels) != len(to) {
		return nil, fmt.Errorf("got %d --label values for %d --to devices; give one label per --to or none", len(labels), len(to))
	}
	if len(labels) == 1 && len(to) > 1 {
		return nil, fmt.Errorf("one --label for %d --to devices is ambiguous; give one label per --to", len(to))
	}
	var out []recipes.RecipeRecipient
	for i, q := range to {
		dev, err := ResolveDevice(ctx, env.TrustStore, q)
		if err != nil {
			return nil, err
		}
		if dev.Revoked || (env.Tombstones != nil && env.Tombstones.HasTombstone(ctx, dev.DeviceID)) {
			return nil, fmt.Errorf("trust for device %q is revoked", dev.LocalLabel)
		}
		label := dev.LocalLabel
		if i < len(labels) {
			label = labels[i]
		}
		if strings.TrimSpace(label) == "" {
			return nil, fmt.Errorf("recipient %q needs a non-empty label (pass --label)", q)
		}
		out = append(out, recipes.RecipeRecipient{DeviceID: dev.DeviceID, Label: label})
	}
	return out, nil
}

// localDeviceLabel is this device's own label for the routine origin
// stamp (V22-PR06): the hostname, falling back to "CLI Device" when the
// hostname is unavailable — the same convention the pairing commands use.
func localDeviceLabel() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return "CLI Device"
}

// outboxEnqueuer adapts the real *outbox.Outbox to the recipes.Enqueuer
// interface so recipe runs enqueue through the production path — one job,
// one attempt per recipient — with no second queue. The routine origin
// label (V22-PR06) is stamped on the job via EnqueueWithProvenance; nil
// provenance would mean an ordinary one-off send, which recipe dispatch
// never produces.
type outboxEnqueuer struct {
	ob *outbox.Outbox
	// senderLabel is this device's own label (localDeviceLabel), passed
	// at construction. It backstops the provenance the engine built: if
	// the engine's SenderLabel is empty, it is filled here so the job's
	// provenance label is never blank.
	senderLabel string
}

func (a outboxEnqueuer) Enqueue(ctx context.Context, paths []string, recipients []recipes.EnqueueRecipient, policy jobs.RetryPolicy, np netpolicy.Policy, provenance *wire.Provenance) (jobs.Job, error) {
	refs := make([]outbox.RecipientRef, len(recipients))
	for i, r := range recipients {
		refs[i] = outbox.RecipientRef{DeviceID: r.DeviceID, Label: r.Label}
	}
	if provenance != nil && provenance.SenderLabel == "" {
		label := a.senderLabel
		if label == "" {
			label = localDeviceLabel()
		}
		cpy := *provenance
		cpy.SenderLabel = label
		provenance = &cpy
	}
	return a.ob.EnqueueWithProvenance(ctx, paths, refs, policy, np, provenance)
}

func runRecipeList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print recipes as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe list: %v\n", err)
		return 1
	}
	entries, err := store.List()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe list: %v\n", err)
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
		_, _ = fmt.Fprintln(stdout, "No recipes. Create one with "+s.cyan("sendbeam recipe create")+".")
		return 0
	}
	for _, e := range entries {
		auto := ""
		if e.AutoSend {
			auto = ", auto-send"
		}
		_, _ = fmt.Fprintf(stdout, "%s  %-16s %-16s %s  %d source(s)  %d recipient(s)%s\n",
			s.cyan(shortRecipeID(e.ID)), e.Name, string(e.Status), e.Trigger,
			e.Sources, e.Recipients, auto)
	}
	if q, err := store.Quarantined(); err == nil && len(q) > 0 {
		_, _ = fmt.Fprintf(stdout, "%s %d unreadable recipe file(s) quarantined (not deleted).\n",
			s.yellow("Warning:"), len(q))
	}
	return 0
}

func runRecipeShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the full recipe JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe show: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe show: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe show: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return 0
	}
	_, _ = fmt.Fprint(stdout, recipes.Preview(r))
	// Grant state beyond the preview summary: whether the stored scope
	// hash still matches the current scope, and the last-run ledger.
	s := newStyleFromWriter(stdout)
	if r.Grant.AutoSend {
		match := "MISMATCH — re-grant with " + s.cyan("sendbeam recipe grant "+shortRecipeID(r.ID))
		if r.Grant.ScopeHash != "" && r.Grant.ScopeHash == r.ScopeHash() {
			match = "matches the current scope"
		}
		_, _ = fmt.Fprintf(stdout, "Grant scope: %s (%s)\n", shortScopeHash(r.Grant.ScopeHash), match)
	}
	if r.Trigger.Kind == recipes.TriggerSchedule {
		if sp, err := recipes.ParseScheduleParams(r.Trigger.Schedule); err != nil {
			_, _ = fmt.Fprintf(stdout, "Next run: schedule is invalid (%v).\n", err)
		} else if next, err := recipes.NextRun(sp, nil, time.Now()); err != nil {
			_, _ = fmt.Fprintf(stdout, "Next run: error: %v.\n", err)
		} else {
			_, _ = fmt.Fprintf(stdout, "Next run: %s.\n", next.Format("2006-01-02 15:04 MST"))
		}
		if r.ScheduleCursor == nil {
			_, _ = fmt.Fprintln(stdout, "Cursor: none yet (adopts on first scheduler tick)")
		} else {
			_, _ = fmt.Fprintf(stdout, "Cursor: %s.\n", r.ScheduleCursor.Format("2006-01-02 15:04:05 MST"))
		}
	}
	if r.LastRun == nil {
		_, _ = fmt.Fprintln(stdout, "Last run: none recorded")
	} else {
		lr := r.LastRun
		line := fmt.Sprintf("Last run: %s via %s — %s",
			lr.At.UTC().Format(time.RFC3339), lr.Trigger, lr.Status)
		if lr.Detail != "" {
			line += " — " + lr.Detail
		}
		_, _ = fmt.Fprintln(stdout, line)
		// V22-PR06: show what the last dispatch actually queued against
		// the budget, with the full job id and the exact cancel command
		// — the job id is actionable here, not just a label.
		if lr.Status == recipes.RunStatusDispatched && lr.JobID != "" {
			_, _ = fmt.Fprintf(stdout, "  Last run sent %s of %s per-run budget (job %s).\n",
				humanBytes(lr.BytesSent), humanBytes(r.Budgets.MaxBytesPerRun), lr.JobID)
			_, _ = fmt.Fprintf(stdout, "  To stop it: %s\n", s.cyan("sendbeam outbox cancel "+lr.JobID))
		} else if lr.JobID != "" {
			_, _ = fmt.Fprintf(stdout, "  Job: %s\n", lr.JobID)
		}
	}
	return 0
}

// parseScheduleParamsFlag parses a --schedule-params JSON object flag and
// validates it as schedule parameters. An empty flag returns nil.
func parseScheduleParamsFlag(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("invalid --schedule-params JSON: %v", err)
	}
	if _, err := recipes.ParseScheduleParams(m); err != nil {
		return nil, err
	}
	return m, nil
}

// applyTriggerFlags wires --trigger/--schedule-params onto a recipe being
// created or edited. It fails closed: schedule params without
// --trigger schedule (and vice versa) are rejected.
func applyTriggerFlags(cmd, trigger string, scheduleParams string, r *recipes.Recipe) error {
	sp, err := parseScheduleParamsFlag(scheduleParams)
	if err != nil {
		return err
	}
	if trigger == "" {
		// Edit path: params may be updated on a schedule trigger without
		// restating the kind.
		if sp == nil {
			return nil
		}
		if r.Trigger.Kind != recipes.TriggerSchedule {
			return fmt.Errorf("%s: --schedule-params needs a schedule trigger (use --trigger schedule)", cmd)
		}
		r.Trigger.Schedule = sp
		return nil
	}
	switch trigger {
	case "manual":
		if sp != nil {
			return fmt.Errorf("%s: --schedule-params needs --trigger schedule", cmd)
		}
		r.Trigger.Kind = recipes.TriggerManual
		r.Trigger.Schedule = nil
	case "schedule":
		if sp == nil {
			if r.Trigger.Kind == recipes.TriggerSchedule && r.Trigger.Schedule != nil {
				return nil // create never hits this; edit keeps existing params
			}
			return fmt.Errorf("%s: --trigger schedule needs --schedule-params JSON", cmd)
		}
		r.Trigger.Kind = recipes.TriggerSchedule
		r.Trigger.Schedule = sp
	default:
		return fmt.Errorf("%s: unknown --trigger %q (manual or schedule)", cmd, trigger)
	}
	return nil
}

func runRecipeCreate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "recipe name")
	var sources stringList
	fs.Var(&sources, "source", "local source file or directory (repeatable)")
	var to stringList
	fs.Var(&to, "to", "target device (device id, @name, or fingerprint; repeatable)")
	var labels stringList
	fs.Var(&labels, "label", "recipient label, aligned by position with --to (default: trust label)")
	networkPolicyFlag := fs.String("network-policy", "", "online (default), prefer-local, or local-only")
	padding := fs.Bool("padding", false, "require strict traffic padding for runs")
	var include stringList
	fs.Var(&include, "include", "glob filter to include, relative to each source root (repeatable)")
	var exclude stringList
	fs.Var(&exclude, "exclude", "glob filter to exclude, relative to each source root (repeatable)")
	recursive := fs.Bool("recursive", true, "descend into directory sources (set false for top level only)")
	budgetBytes := fs.Int64("budget-bytes", 0, "max bytes per run (0 = default 10 GiB)")
	budgetFiles := fs.Int64("budget-files", 0, "max files per run (0 = default 10000)")
	trigger := fs.String("trigger", "manual", "trigger kind: manual or schedule")
	scheduleParams := fs.String("schedule-params", "", `schedule parameters as JSON, e.g. '{"kind":"daily","at":"14:30","tz":"Asia/Calcutta"}'`)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	if strings.TrimSpace(*name) == "" || len(sources) == 0 || len(to) == 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe create: need --name, at least one --source, and at least one --to")
		fs.Usage()
		return 2
	}
	if _, err := netpolicy.Parse(*networkPolicyFlag); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}
	recipients, err := resolveRecipeRecipients(ctx, env, to, labels)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}

	r, err := recipes.NewRecipe(*name, time.Now().UTC())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}
	for _, src := range sources {
		abs, err := filepath.Abs(src)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: resolve source %q: %v\n", src, err)
			return 1
		}
		r.Sources = append(r.Sources, recipes.RecipeSource{Path: filepath.Clean(abs), Recursive: *recursive})
	}
	r.Recipients = recipients
	r.NetworkPolicy = *networkPolicyFlag
	r.RequirePadding = *padding
	r.Include = include
	r.Exclude = exclude
	if *budgetBytes > 0 {
		r.Budgets.MaxBytesPerRun = *budgetBytes
	}
	if *budgetFiles > 0 {
		r.Budgets.MaxFilesPerRun = *budgetFiles
	}
	if err := applyTriggerFlags("sendbeam recipe create", *trigger, *scheduleParams, &r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 2
	}
	r.Grant.ScopeHash = r.ScopeHash()

	// Validate recipients against the trust store at create time: a
	// recipe must never be saved with an untrusted recipient.
	if err := recipes.ValidateRecipients(ctx, env.TrustStore, r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe create: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s)\n", s.green("Created"), r.Name, s.cyan(shortRecipeID(r.ID)))
	_, _ = fmt.Fprintf(stdout, "  Status: %s. Preview with %s, then %s to allow runs.\n",
		s.yellow(string(r.Status)), s.cyan("sendbeam recipe preview "+shortRecipeID(r.ID)),
		s.cyan("sendbeam recipe approve "+shortRecipeID(r.ID)))
	return 0
}

func runRecipeEdit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe edit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "rename the recipe")
	var addSources stringList
	fs.Var(&addSources, "add-source", "add a local source root (repeatable)")
	var removeSources stringList
	fs.Var(&removeSources, "remove-source", "remove a source root by path (repeatable)")
	var addRecipients stringList
	fs.Var(&addRecipients, "add-recipient", "add a trusted recipient device (repeatable)")
	var removeRecipients stringList
	fs.Var(&removeRecipients, "remove-recipient", "remove a recipient by device id (repeatable)")
	var labels stringList
	fs.Var(&labels, "label", "label for --add-recipient, aligned by position")
	networkPolicyFlag := fs.String("network-policy", "", "set network policy: online, prefer-local, local-only (empty = unchanged)")
	setPadding := fs.Bool("padding", false, "require strict traffic padding")
	unsetPadding := fs.Bool("no-padding", false, "stop requiring traffic padding")
	recursive := fs.Bool("recursive", true, "added directory sources descend recursively")
	budgetBytes := fs.Int64("budget-bytes", 0, "set max bytes per run (0 = unchanged)")
	budgetFiles := fs.Int64("budget-files", 0, "set max files per run (0 = unchanged)")
	trigger := fs.String("trigger", "", "set trigger kind: manual or schedule (empty = unchanged)")
	scheduleParams := fs.String("schedule-params", "", `set schedule parameters as JSON, e.g. '{"kind":"daily","at":"14:30","tz":"Asia/Calcutta"}'`)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe edit: need exactly one <id>")
		fs.Usage()
		return 2
	}
	if *setPadding && *unsetPadding {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe edit: --padding and --no-padding conflict")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 1
	}

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 1
	}

	if strings.TrimSpace(*name) != "" {
		r.Name = *name
	}
	for _, src := range addSources {
		abs, err := filepath.Abs(src)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: resolve source %q: %v\n", src, err)
			return 1
		}
		r.Sources = append(r.Sources, recipes.RecipeSource{Path: filepath.Clean(abs), Recursive: *recursive})
	}
	if len(removeSources) > 0 {
		keep := r.Sources[:0]
		for _, s := range r.Sources {
			drop := false
			for _, rm := range removeSources {
				if s.Path == filepath.Clean(rm) {
					drop = true
					break
				}
			}
			if !drop {
				keep = append(keep, s)
			}
		}
		r.Sources = keep
	}
	if len(addRecipients) > 0 {
		added, err := resolveRecipeRecipients(ctx, env, addRecipients, labels)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
			return 1
		}
		r.Recipients = append(r.Recipients, added...)
	}
	if len(removeRecipients) > 0 {
		keep := r.Recipients[:0]
		for _, c := range r.Recipients {
			drop := false
			for _, rm := range removeRecipients {
				if strings.EqualFold(c.DeviceID, strings.TrimSpace(rm)) {
					drop = true
					break
				}
			}
			if !drop {
				keep = append(keep, c)
			}
		}
		r.Recipients = keep
	}
	if *networkPolicyFlag != "" {
		if _, err := netpolicy.Parse(*networkPolicyFlag); err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
			return 2
		}
		r.NetworkPolicy = *networkPolicyFlag
	}
	if *setPadding {
		r.RequirePadding = true
	}
	if *unsetPadding {
		r.RequirePadding = false
	}
	if *budgetBytes > 0 {
		r.Budgets.MaxBytesPerRun = *budgetBytes
	}
	if *budgetFiles > 0 {
		r.Budgets.MaxFilesPerRun = *budgetFiles
	}

	if err := applyTriggerFlags("sendbeam recipe edit", *trigger, *scheduleParams, &r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 2
	}
	// ValidateRecipients at edit time too: trust may have changed since
	// the recipe was composed.
	if err := recipes.ValidateRecipients(ctx, env.TrustStore, r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 1
	}
	// ApplyUpdate enforces the material-change rule: widening the scope
	// revokes automation consent and forces re-approval.
	updated, err := recipes.ApplyUpdate(store, r)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe edit: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s); status now %s.\n",
		s.green("Updated"), updated.Name, s.cyan(shortRecipeID(updated.ID)), s.yellow(string(updated.Status)))
	return 0
}

func runRecipeDuplicate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe duplicate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "name for the copy")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 || strings.TrimSpace(*name) == "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe duplicate: need <id> and --name NEW")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe duplicate: %v\n", err)
		return 1
	}
	src, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe duplicate: %v\n", err)
		return 1
	}
	dup, err := recipes.NewRecipe(*name, time.Now().UTC())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe duplicate: %v\n", err)
		return 1
	}
	dup.Sources = append([]recipes.RecipeSource(nil), src.Sources...)
	dup.Recipients = append([]recipes.RecipeRecipient(nil), src.Recipients...)
	dup.NetworkPolicy = src.NetworkPolicy
	dup.RequirePadding = src.RequirePadding
	dup.Include = append([]string(nil), src.Include...)
	dup.Exclude = append([]string(nil), src.Exclude...)
	dup.Trigger = src.Trigger
	dup.ExpiresAt = src.ExpiresAt
	dup.Budgets = src.Budgets
	// Fresh id, approval-required status, no grant: NewRecipe already set
	// those; just refresh the scope hash for the copied scope.
	dup.Grant.ScopeHash = dup.ScopeHash()
	if err := store.Save(dup); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe duplicate: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q as %q (id %s); status %s.\n",
		s.green("Duplicated"), src.Name, dup.Name, s.cyan(shortRecipeID(dup.ID)), s.yellow(string(dup.Status)))
	return 0
}

func runRecipeDelete(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe delete: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe delete: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe delete: %v\n", err)
		return 1
	}
	if err := store.Delete(r.ID); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe delete: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s).\n", s.yellow("Deleted"), r.Name, s.cyan(shortRecipeID(r.ID)))
	return 0
}

func runRecipeApprove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe approve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe approve: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe approve: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe approve: %v\n", err)
		return 1
	}
	if r.Status == recipes.RecipeManual {
		_, _ = fmt.Fprintf(stdout, "Recipe %q is already approved for manual runs.\n", r.Name)
		return 0
	}
	if r.Status == recipes.RecipeDisabled {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe approve: recipe %q is disabled; run `sendbeam recipe enable %s` first, then approve\n", r.Name, shortRecipeID(r.ID))
		return 1
	}
	// The human at the keyboard IS the approval: this explicit command is
	// the consent record. It never grants auto-send — only manual runs.
	r.Status = recipes.RecipeManual
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe approve: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q for manual one-shot runs (id %s).\n",
		s.green("Approved"), r.Name, s.cyan(shortRecipeID(r.ID)))
	return 0
}

func runRecipeGrant(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe grant: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe grant: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe grant: %v\n", err)
		return 1
	}
	// Explicit user consent: this command, typed by the human at the
	// keyboard, IS the authorization. It records auto-send consent for
	// the routine runner; it never runs anything itself.
	if err := recipes.GrantAutomation(&r, time.Now().UTC()); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe grant: %v\n", err)
		return 1
	}
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe grant: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s auto-send for recipe %q (id %s).\n",
		s.green("Granted"), r.Name, s.cyan(shortRecipeID(r.ID)))
	_, _ = fmt.Fprintf(stdout, "  Consent v%d recorded at %s for scope %s.\n",
		r.Grant.ConsentVersion, r.Grant.GrantedAt.UTC().Format(time.RFC3339), shortScopeHash(r.Grant.ScopeHash))
	_, _ = fmt.Fprintln(stdout, "  Any material change (sources, recipients, trigger, network policy,")
	_, _ = fmt.Fprintln(stdout, "  padding, filters, expiry, budgets) revokes this grant — re-grant")
	_, _ = fmt.Fprintln(stdout, "  explicitly afterwards. The receiver's acceptance policy is separate")
	_, _ = fmt.Fprintln(stdout, "  and unaffected.")
	return 0
}

func runRecipeRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe revoke: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe revoke: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe revoke: %v\n", err)
		return 1
	}
	had := r.Grant.AutoSend
	recipes.RevokeAutomation(&r)
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe revoke: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	if had {
		_, _ = fmt.Fprintf(stdout, "%s auto-send for recipe %q (id %s).\n",
			s.yellow("Revoked"), r.Name, s.cyan(shortRecipeID(r.ID)))
	} else {
		_, _ = fmt.Fprintf(stdout, "Recipe %q had no active auto-send grant; nothing to revoke (id %s).\n",
			r.Name, s.cyan(shortRecipeID(r.ID)))
	}
	_, _ = fmt.Fprintf(stdout, "  Status is unchanged (%s): manual runs still work, automated dispatch is refused.\n",
		string(r.Status))
	return 0
}

func shortScopeHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// runRecipeDisable implements `sendbeam recipe disable <id>`: the routine
// is switched off — status "disabled" — so every future dispatch (watch,
// schedule, retry, and manual alike) is refused and the watcher's dynamic
// reload plus the scheduler's reconciliation drop it. A dispatch already
// admitted keeps running to completion: disable stops the NEXT send, never
// the one already moving bytes. The automation grant is left untouched
// (but inert); `recipe enable` revokes it explicitly as the safe default.
func runRecipeDisable(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe disable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe disable: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe disable: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe disable: %v\n", err)
		return 1
	}
	if r.Status == recipes.RecipeDisabled {
		_, _ = fmt.Fprintf(stdout, "Recipe %q is already disabled (id %s).\n", r.Name, shortRecipeID(r.ID))
		return 0
	}
	recipes.Disable(&r)
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe disable: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s): no future dispatch of any kind will run.\n",
		s.yellow("Disabled"), r.Name, s.cyan(shortRecipeID(r.ID)))
	_, _ = fmt.Fprintln(stdout, "  An in-flight dispatch, if any, runs to completion; re-enable with `sendbeam recipe enable <id>`.")
	return 0
}

// runRecipeEnable implements `sendbeam recipe enable <id>`: a disabled
// routine returns to life through the safe default — status
// "approval-required" and its automation consent revoked, even if it was
// granted before. Nothing dispatches until a person re-reviews: manual
// runs need `recipe approve <id>` first, and automated dispatch needs a
// fresh `recipe grant <id>` after that.
func runRecipeEnable(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe enable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe enable: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe enable: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe enable: %v\n", err)
		return 1
	}
	if r.Status != recipes.RecipeDisabled {
		_, _ = fmt.Fprintf(stdout, "Recipe %q is not disabled (status %s); nothing to enable (id %s).\n",
			r.Name, string(r.Status), shortRecipeID(r.ID))
		return 0
	}
	hadGrant := r.Grant.AutoSend
	recipes.Enable(&r)
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe enable: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s): status is now %s.\n",
		s.green("Enabled"), r.Name, s.cyan(shortRecipeID(r.ID)), s.yellow(string(r.Status)))
	if hadGrant {
		_, _ = fmt.Fprintln(stdout, "  Its previous auto-send consent was revoked as the safe default.")
	}
	_, _ = fmt.Fprintln(stdout, "  Next steps: `sendbeam recipe approve <id>` for manual runs, then `sendbeam recipe grant <id>` to allow automation.")
	return 0
}

func runRecipePreview(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the versioned plan DTO JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe preview: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe preview: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe preview: %v\n", err)
		return 1
	}
	// Dry-run only: Resolve never takes an Enqueuer, so no job can be
	// created here by construction.
	plan, err := recipes.Resolve(r, recipes.ResolveOptions{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe preview: %v\n", err)
		return 1
	}
	if *jsonOutput {
		_, _ = fmt.Fprintln(stdout, string(recipes.PlanDTO(plan)))
		return 0
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprint(stdout, recipes.Preview(r))
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintf(stdout, "Dry-run plan: %d file(s), %s; %d recipient(s).\n",
		len(plan.Files), humanBytes(plan.TotalBytes), len(plan.Recipients))
	for _, w := range plan.Warnings {
		_, _ = fmt.Fprintf(stdout, "  %s %s\n", s.yellow("warning:"), w)
	}
	for _, f := range plan.Files {
		_, _ = fmt.Fprintf(stdout, "  %s  %s\n", f.Path, humanBytes(f.Size))
	}
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, s.dim("This is a dry-run preview: it sends nothing and creates no jobs."))
	_, _ = fmt.Fprintln(stdout, s.dim("A run re-resolves the sources, so files may differ by run time."))
	return 0
}

func runRecipeRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the enqueued job as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe run: need exactly one <id>")
		fs.Usage()
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe run: %v\n", err)
		return 1
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe run: %v\n", err)
		return 1
	}
	jobStore, err := openOutboxStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe run: %v\n", err)
		return 1
	}
	// The production outbox: one call creates ONE job with one attempt per
	// recipient. No second queue, no daemon needed — the job waits in the
	// outbox until `sendbeam outbox dispatch` sends it.
	ob := outbox.New(jobStore, nil)
	// The routine runner (not the bare RunWithTrigger) so the dispatch
	// records the last-run ledger — status, job id, bytes sent — that
	// `sendbeam recipe show` prints with the cancel command.
	rn := recipes.NewRunner(
		recipes.RunDeps{Store: store, Trust: env.TrustStore, SenderLabel: localDeviceLabel()},
		outboxEnqueuer{ob: ob, senderLabel: localDeviceLabel()},
		recipes.RunnerOptions{},
	)
	job, err := rn.Dispatch(ctx, positionals[0], recipes.TriggerManual)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe run: %v\n", err)
		return 1
	}
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(jobSummary(job))
		return 0
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s job %s: %d file(s), %s for %d recipient(s); network policy: %s.\n",
		s.green("Enqueued"), s.cyan(shortJobID(job.JobID)), len(job.Files), humanBytes(job.TotalSize),
		len(job.Attempts), job.EffectiveNetworkPolicy())
	_, _ = fmt.Fprintf(stdout, "  Run %s to send due attempts.\n", s.cyan("sendbeam outbox dispatch"))
	return 0
}

// runRecipeWatch implements `sendbeam recipe watch <id>`: it runs the
// recipe's filesystem watcher in the foreground until SIGINT/SIGTERM,
// printing what the watcher sees and does. The watcher never sends files
// itself — each quiet window ends in one ordinary TriggerWatch dispatch
// through the routine runner, which re-validates the grant, trust, files
// and budgets before enqueueing one job.
func runRecipeWatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe watch: need exactly one <id>")
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return watchRecipe(ctx, positionals[0], *configDir, stdout, stderr)
}

// watchRecipe starts the watcher for one recipe and blocks until ctx is
// done, then stops the watcher cleanly. It is split out from
// runRecipeWatch so tests can drive it with a cancelable context instead
// of a real signal.
func watchRecipe(ctx context.Context, id, configDir string, stdout, stderr io.Writer) int {
	env, err := InitCLIEnvironment(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	store, err := openRecipeStore(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, id)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	jobStore, err := openOutboxStore(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	ob := outbox.New(jobStore, nil)
	runner := recipes.NewRunner(
		recipes.RunDeps{Store: store, Trust: env.TrustStore, SenderLabel: localDeviceLabel()},
		outboxEnqueuer{ob: ob, senderLabel: localDeviceLabel()},
		recipes.RunnerOptions{},
	)
	printEvent := func(format string, args ...any) {
		_, _ = fmt.Fprintf(stdout, format+"\n", args...)
	}
	w, err := recipes.NewWatcher(store, runner, r.ID, recipes.WatchOptions{
		OnEvent: func(evt recipes.WatchEvent) {
			switch evt.Kind {
			case recipes.WatchEventChange:
				printEvent("change detected in %s, waiting for quiet…", evt.Root)
			case recipes.WatchEventDispatching:
				printEvent("dispatching…")
			case recipes.WatchEventDispatched:
				printEvent("dispatched job %s", shortJobID(evt.JobID))
			case recipes.WatchEventRefused:
				printEvent("dispatch refused: %s", evt.Detail)
			case recipes.WatchEventSkipped:
				printEvent("skipped: %s", evt.Detail)
			case recipes.WatchEventError:
				printEvent("watch error: %s", evt.Detail)
			}
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	if err := w.Start(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: %v\n", err)
		return 1
	}
	printEvent("Watching recipe %q (%d source root(s)) — press Ctrl+C to stop.", r.Name, len(r.Sources))
	<-ctx.Done()
	if err := w.Stop(); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe watch: stop: %v\n", err)
		return 1
	}
	printEvent("Watch stopped.")
	return 0
}

func runRecipeExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", "", "write to FILE instead of stdout")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe export: need exactly one <id>")
		fs.Usage()
		return 2
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe export: %v\n", err)
		return 1
	}
	r, err := loadRecipe(store, positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe export: %v\n", err)
		return 1
	}
	// Export is secret-free by construction: the schema holds no key
	// material, credentials, or reusable secrets.
	data, err := recipes.Export(r)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe export: %v\n", err)
		return 1
	}
	if *outPath == "" {
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}
	if err := os.WriteFile(*outPath, append(data, '\n'), 0o600); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe export: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q to %s.\n", s.green("Exported"), r.Name, *outPath)
	return 0
}

func runRecipeImport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 1 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe import: need exactly one <file>")
		fs.Usage()
		return 2
	}
	data, err := os.ReadFile(positionals[0])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe import: %v\n", err)
		return 1
	}
	// Import never grants anything: status is forced to disabled, any
	// auto-send consent is cleared.
	r, err := recipes.Import(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe import: %v\n", err)
		return 1
	}
	store, err := openRecipeStore(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe import: %v\n", err)
		return 1
	}
	if err := store.Save(r); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe import: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	_, _ = fmt.Fprintf(stdout, "%s recipe %q (id %s).\n", s.green("Imported"), r.Name, s.cyan(shortRecipeID(r.ID)))
	_, _ = fmt.Fprintf(stdout, "  Status: %s — imports never run automatically. Review, edit, then %s.\n",
		s.yellow(string(r.Status)), s.cyan("sendbeam recipe approve "+shortRecipeID(r.ID)))
	return 0
}

// runRecipeScheduler implements `sendbeam recipe scheduler`: it hosts every
// enabled schedule-triggered recipe in the foreground and runs due
// occurrences, until SIGINT/SIGTERM. There is no daemon and no cron: the
// scheduler is an ordinary foreground process the user starts and stops.
func runRecipeScheduler(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("recipe scheduler", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	positionals := parseArgs(fs, args)
	if len(positionals) != 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam recipe scheduler: takes no arguments")
		fs.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return scheduleRecipes(ctx, *configDir, stdout, stderr)
}

// scheduleRecipes is the testable body of `sendbeam recipe scheduler`: it
// builds the recipe runner and scheduler, prints scheduler events, and
// blocks until ctx is cancelled. SIGINT/SIGTERM cancels ctx and the stop is
// clean (exit 0).
func scheduleRecipes(ctx context.Context, configDir string, stdout, stderr io.Writer) int {
	env, err := InitCLIEnvironment(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe scheduler: %v\n", err)
		return 1
	}
	store, err := openRecipeStore(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe scheduler: %v\n", err)
		return 1
	}
	jobStore, err := openOutboxStore(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe scheduler: %v\n", err)
		return 1
	}
	runner := recipes.NewRunner(
		recipes.RunDeps{Store: store, Trust: env.TrustStore, SenderLabel: localDeviceLabel()},
		outboxEnqueuer{ob: outbox.New(jobStore, nil), senderLabel: localDeviceLabel()},
		recipes.RunnerOptions{},
	)
	s := newStyleFromWriter(stdout)
	sched, err := recipes.NewScheduler(store, runner, recipes.ScheduleOptions{
		OnEvent: func(evt recipes.ScheduleEvent) {
			ts := time.Now().Format("15:04:05")
			id := shortRecipeID(evt.RecipeID)
			detail := evt.Detail
			if detail == "" && evt.Err != nil {
				detail = evt.Err.Error()
			}
			name := evt.Name
			if name == "" {
				name = id
			}
			switch evt.Kind {
			case recipes.ScheduleEventDue:
				_, _ = fmt.Fprintf(stdout, "%s due: %q (%s)\n", ts, name, detail)
			case recipes.ScheduleEventDispatching:
				_, _ = fmt.Fprintf(stdout, "%s dispatching: %q\n", ts, name)
			case recipes.ScheduleEventDispatched:
				_, _ = fmt.Fprintf(stdout, "%s dispatched: %q via schedule (job %s)\n", ts, name, shortJobID(evt.JobID))
			case recipes.ScheduleEventRefused:
				_, _ = fmt.Fprintf(stdout, "%s refused: %q — %s\n", ts, name, detail)
			case recipes.ScheduleEventSkipped:
				_, _ = fmt.Fprintf(stdout, "%s skipped: %q — %s\n", ts, name, detail)
			case recipes.ScheduleEventCatchup:
				_, _ = fmt.Fprintf(stdout, "%s catch-up: %q — %s\n", ts, name, detail)
			case recipes.ScheduleEventError:
				_, _ = fmt.Fprintf(stderr, "%s scheduler error: %s\n", ts, detail)
			}
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe scheduler: %v\n", err)
		return 1
	}
	if err := sched.Start(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam recipe scheduler: %v\n", err)
		return 1
	}
	defer func() { _ = sched.Stop() }()
	hosts := sched.Hosts()
	if len(hosts) == 0 {
		_, _ = fmt.Fprintf(stdout, "%s (no enabled schedule-triggered recipes — Ctrl+C to stop)\n",
			s.bold("Scheduler running."))
	} else {
		_, _ = fmt.Fprintf(stdout, "%s hosting %d schedule-triggered recipe(s) — Ctrl+C to stop.\n",
			s.bold("Scheduler running,"), len(hosts))
		for id, sp := range hosts {
			_, _ = fmt.Fprintf(stdout, "  - %s: %s\n", s.cyan(shortRecipeID(id)), sp.HumanWords())
		}
	}
	<-ctx.Done()
	_, _ = fmt.Fprintf(stdout, "%s\n", s.dim("Scheduler stopped."))
	return 0
}
