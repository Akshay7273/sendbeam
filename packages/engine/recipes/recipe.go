// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// RecipeSchemaVersion is the current Recipe schema. Readers refuse
// (quarantine) records whose schema they do not understand rather than
// truncating them. Watch trigger detail (V22-PR04) validated inside the
// existing trigger.watch map shape, so no schema bump was needed;
// schedule detail (V22-PR05) may need one if its wire shape changes.
const RecipeSchemaVersion = 1

// RecipeStatus is the lifecycle state of a recipe.
type RecipeStatus string

const (
	// RecipeDisabled never runs, manually or automatically.
	RecipeDisabled RecipeStatus = "disabled"
	// RecipeManual runs only as an explicit one-shot; one-shot runs never
	// need an automation grant.
	RecipeManual RecipeStatus = "manual"
	// RecipeApprovalRequired is the default for new, imported and
	// materially changed recipes: nothing dispatches until a person
	// reviews and approves it.
	RecipeApprovalRequired RecipeStatus = "approval-required"
)

// RunStatus is the outcome class of one dispatch attempt, recorded in the
// last-run ledger.
type RunStatus string

const (
	// RunStatusDispatched means the attempt passed every gate and
	// enqueued exactly one job.
	RunStatusDispatched RunStatus = "dispatched"
	// RunStatusRefused means a gate refused the attempt (disabled
	// recipe, missing/invalid grant, expired, revoked recipient,
	// budget exceeded, runner busy, ...). The attempt never enqueued.
	RunStatusRefused RunStatus = "refused"
	// RunStatusFailed means the attempt failed unexpectedly after
	// passing the gates (enqueue error, context cancellation, ...).
	RunStatusFailed RunStatus = "failed"
	// RunStatusSkipped means the attempt was deduplicated: the recipe
	// already had a dispatch in flight, so this attempt did nothing.
	RunStatusSkipped RunStatus = "skipped"
)

// RecipeRunInfo is one last-run ledger entry: when the most recent
// dispatch attempt happened, what triggered it, which job it produced (if
// any), how it ended, and a short human-readable detail. It is stored on
// the recipe record (durable, checksummed) and is the audit trail the
// routine-management UI (V22-PR06) reads.
type RecipeRunInfo struct {
	// At is when the attempt finished (RFC3339, UTC).
	At time.Time `json:"at"`
	// Trigger is the reason that started the attempt.
	Trigger TriggerReason `json:"trigger"`
	// JobID is the enqueued job id, set only for dispatched runs.
	JobID string `json:"jobId,omitempty"`
	// Status is the outcome class (dispatched/refused/failed/skipped).
	Status RunStatus `json:"status"`
	// Detail is a short human-readable note (e.g. the refusal reason).
	Detail string `json:"detail,omitempty"`
}

// TriggerReason names what started a recipe dispatch. Manual is the human
// at the keyboard; watch, schedule and retry are automated reasons that
// the native routine runner (V22-PR03) serves. Watch trigger sources
// arrived in V22-PR04; schedule sources arrive in V22-PR05.
type TriggerReason string

// Trigger kinds. "schedule" detail lands in V22-PR05; until then its
// reserved parameter map must be empty. Watch parameters are validated by
// ParseWatchParams.
const (
	TriggerManual   TriggerReason = "manual"
	TriggerWatch    TriggerReason = "watch"
	TriggerSchedule TriggerReason = "schedule"
	// TriggerRetry marks a dispatch that re-attempts a previously refused
	// or failed automated run. Like watch and schedule, it requires a
	// valid automation grant; only TriggerManual never does.
	TriggerRetry TriggerReason = "retry"
)

// RecipeSource is one explicit local source root: an absolute local path,
// file or directory. Recursive applies to directories.
type RecipeSource struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

// RecipeRecipient is one fixed authenticated recipient device. The recipe
// names the device; the destination on that device is receiver-approved
// policy, never a sender-chosen remote path.
type RecipeRecipient struct {
	DeviceID string `json:"deviceId"`
	Label    string `json:"label"`
}

// RecipeTrigger describes what may start a run. Watch carries the
// debounce/cooldown parameters defined below (V22-PR04); Schedule stays a
// reserved parameter map until V22-PR05 and must be empty.
type RecipeTrigger struct {
	Kind     TriggerReason  `json:"kind"`
	Watch    map[string]any `json:"watch,omitempty"`
	Schedule map[string]any `json:"schedule,omitempty"`
}

// Watch trigger parameter keys and their bounds. The watched roots are
// always the recipe's own sources — explicitly composed by the user —
// never anything the watcher discovers on its own.
const (
	// WatchParamDebounceMS names the quiet window (milliseconds) after the
	// last filesystem event before a debounced dispatch fires.
	WatchParamDebounceMS = "debounce_ms"
	// WatchParamCooldownMS names the minimum interval (milliseconds)
	// between two dispatches of the same recipe (flap protection).
	WatchParamCooldownMS = "cooldown_ms"
	// WatchParamRecursive names whether subdirectories of source roots are
	// watched. When false, only top-level events arm the debounce timer;
	// the resolver's per-source Recursive flag still governs what a
	// dispatch actually sends.
	WatchParamRecursive = "recursive"

	// DefaultWatchDebounce is the quiet window when debounce_ms is unset.
	DefaultWatchDebounce = 2000 * time.Millisecond
	// MinWatchDebounce / MaxWatchDebounce bound debounce_ms.
	MinWatchDebounce = 250 * time.Millisecond
	MaxWatchDebounce = 60000 * time.Millisecond
	// DefaultWatchCooldown is the flap-protection interval when
	// cooldown_ms is unset.
	DefaultWatchCooldown = 10000 * time.Millisecond
	// MinWatchCooldown / MaxWatchCooldown bound cooldown_ms. Zero is
	// allowed: it disables flap protection.
	MinWatchCooldown = 0 * time.Millisecond
	MaxWatchCooldown = 3600000 * time.Millisecond
	// DefaultWatchRecursive is the subdirectory-watching default when the
	// recursive flag is unset.
	DefaultWatchRecursive = true
)

// WatchParams is the parsed, validated v1 watch trigger configuration.
type WatchParams struct {
	// Debounce is the quiet window after the last filesystem event before
	// dispatching.
	Debounce time.Duration
	// Cooldown is the minimum interval between two dispatches of the same
	// recipe.
	Cooldown time.Duration
	// Recursive reports whether subdirectories of source roots are
	// watched. It governs *detection* scope only: what a dispatch sends
	// is still governed by each source's own Recursive flag at resolve
	// time. A subdir change can therefore trigger a dispatch whose plan
	// contains only top-level files — wasteful but never wrong.
	Recursive bool
}

// ParseWatchParams validates a raw trigger.watch parameter map and
// returns the effective configuration with defaults applied. It fails
// closed: unknown keys, non-JSON-number/bool values, fractional
// milliseconds and out-of-range values are all rejected. A nil or empty
// map yields the defaults.
func ParseWatchParams(watch map[string]any) (WatchParams, error) {
	wp := WatchParams{
		Debounce:  DefaultWatchDebounce,
		Cooldown:  DefaultWatchCooldown,
		Recursive: DefaultWatchRecursive,
	}
	for key, val := range watch {
		switch key {
		case WatchParamDebounceMS:
			ms, err := watchParamMillis(key, val)
			if err != nil {
				return WatchParams{}, err
			}
			d := time.Duration(ms) * time.Millisecond
			if d < MinWatchDebounce || d > MaxWatchDebounce {
				return WatchParams{}, wire.Errorf(wire.CodeStorage,
					"recipes: trigger.watch debounce_ms %d out of range [%d, %d]",
					ms, MinWatchDebounce.Milliseconds(), MaxWatchDebounce.Milliseconds())
			}
			wp.Debounce = d
		case WatchParamCooldownMS:
			ms, err := watchParamMillis(key, val)
			if err != nil {
				return WatchParams{}, err
			}
			d := time.Duration(ms) * time.Millisecond
			if d < MinWatchCooldown || d > MaxWatchCooldown {
				return WatchParams{}, wire.Errorf(wire.CodeStorage,
					"recipes: trigger.watch cooldown_ms %d out of range [%d, %d]",
					ms, MinWatchCooldown.Milliseconds(), MaxWatchCooldown.Milliseconds())
			}
			wp.Cooldown = d
		case WatchParamRecursive:
			b, ok := val.(bool)
			if !ok {
				return WatchParams{}, wire.Errorf(wire.CodeStorage,
					"recipes: trigger.watch recursive must be a JSON boolean, got %T", val)
			}
			wp.Recursive = b
		default:
			return WatchParams{}, wire.Errorf(wire.CodeStorage,
				"recipes: unknown trigger.watch parameter %q (supported: debounce_ms, cooldown_ms, recursive)", key)
		}
	}
	return wp, nil
}

// watchParamMillis converts a JSON number parameter to whole milliseconds.
// Fractional values are rejected: sub-millisecond debounce/cooldown is
// meaningless and usually a units bug (seconds passed as milliseconds).
func watchParamMillis(key string, val any) (int64, error) {
	var f float64
	switch v := val.(type) {
	case float64:
		f = v
	case float32:
		f = float64(v)
	case int:
		f = float64(v)
	case int8:
		f = float64(v)
	case int16:
		f = float64(v)
	case int32:
		f = float64(v)
	case int64:
		f = float64(v)
	case uint:
		f = float64(v)
	case uint8:
		f = float64(v)
	case uint16:
		f = float64(v)
	case uint32:
		f = float64(v)
	case uint64:
		f = float64(v)
	default:
		return 0, wire.Errorf(wire.CodeStorage,
			"recipes: trigger.watch %s must be a JSON number, got %T", key, val)
	}
	if f != float64(int64(f)) {
		return 0, wire.Errorf(wire.CodeStorage,
			"recipes: trigger.watch %s must be whole milliseconds, got %v", key, val)
	}
	return int64(f), nil
}

// RecipeBudgets caps what one recipe may consume. Budgets are material
// scope: loosening a budget broadens the automation grant, so any budget
// change invalidates prior consent (see ApplyUpdate).
type RecipeBudgets struct {
	MaxBytesPerRun    int64 `json:"maxBytesPerRun,omitempty"`
	MaxFilesPerRun    int64 `json:"maxFilesPerRun,omitempty"`
	MaxConcurrentRuns int   `json:"maxConcurrentRuns,omitempty"`
}

// RecipeGrant is the explicit sender-side automation grant. AutoSend allows
// the native routine runner to dispatch this recipe without a per-run
// confirmation; it says nothing about the receiver, whose acceptance
// policy is separate (trust.TrustPolicy on the receiver side).
type RecipeGrant struct {
	// AutoSend is the explicit opt-in for automatic dispatch.
	AutoSend bool `json:"autoSend"`
	// ConsentVersion counts material-scope revisions; it is bumped every
	// time a material change revokes the grant.
	ConsentVersion int `json:"consentVersion"`
	// GrantedAt is when the current consent was given (RFC3339, UTC).
	// Zero means no active consent.
	GrantedAt time.Time `json:"grantedAt,omitempty"`
	// ScopeHash is the ScopeHash() of the material scope the consent was
	// given for. An AutoSend grant is only meaningful while it matches
	// the recipe's current ScopeHash.
	ScopeHash string `json:"scopeHash"`
}

// Recipe is one saved handoff workflow.
type Recipe struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	// CreatedAt / UpdatedAt are RFC3339 UTC timestamps.
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Name is the human label shown in the composer and preview.
	Name string `json:"name"`
	// Status is the recipe lifecycle state.
	Status RecipeStatus `json:"status"`
	// Sources are the explicit local source roots (>= 1).
	Sources []RecipeSource `json:"sources"`
	// Recipients are the fixed authenticated recipients (>= 1).
	Recipients []RecipeRecipient `json:"recipients"`
	// NetworkPolicy is the canonical policy name ("online",
	// "prefer-local", "local-only"); empty means "online".
	NetworkPolicy string `json:"networkPolicy,omitempty"`
	// RequirePadding enforces strict traffic padding for runs of this
	// recipe, separate from the network policy.
	RequirePadding bool `json:"requirePadding,omitempty"`
	// Include / Exclude are glob filter lists (optional).
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Trigger describes what may start a run.
	Trigger RecipeTrigger `json:"trigger"`
	// ExpiresAt, when non-zero, is the hard deadline: no run starts after
	// it (RFC3339, UTC).
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	// Budgets caps bytes/files per run and concurrent runs.
	Budgets RecipeBudgets `json:"budgets"`
	// Grant is the explicit sender-side automation grant.
	Grant RecipeGrant `json:"grant"`
	// LastRun is the most recent dispatch attempt (any trigger reason,
	// including refusals). Nil when no attempt has been recorded yet.
	// Written by the routine runner after every dispatch attempt; never
	// set by create/duplicate/import.
	LastRun *RecipeRunInfo `json:"lastRun,omitempty"`
	// Checksum covers the canonical encoding of every other field.
	Checksum string `json:"checksum"`
}

// DefaultBudgets is the conservative out-of-the-box budget: 10 GiB and
// 10k files per run, one concurrent run.
func DefaultBudgets() RecipeBudgets {
	return RecipeBudgets{
		MaxBytesPerRun:    10 * 1024 * 1024 * 1024,
		MaxFilesPerRun:    10000,
		MaxConcurrentRuns: 1,
	}
}

// NewRecipe constructs a validated recipe that never runs automatically:
// status "approval-required", no AutoSend grant, manual trigger, default
// budgets. Sources and recipients are added by the caller (the composer in
// V22-PR02) before the recipe can be saved: the store and the dispatch
// path always run the full ValidateRecipe, which requires >= 1 of each, so
// an un-composed recipe can never be persisted or dispatched.
func NewRecipe(name string, now time.Time) (Recipe, error) {
	if strings.TrimSpace(name) == "" {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: recipe name must not be empty")
	}
	id, err := mintRecipeID()
	if err != nil {
		return Recipe{}, err
	}
	now = now.UTC()
	r := Recipe{
		SchemaVersion: RecipeSchemaVersion,
		ID:            id,
		CreatedAt:     now,
		UpdatedAt:     now,
		Name:          name,
		Status:        RecipeApprovalRequired,
		Trigger:       RecipeTrigger{Kind: TriggerManual},
		Budgets:       DefaultBudgets(),
	}
	r.Grant.ScopeHash = r.ScopeHash()
	if err := validateRecipe(r, false); err != nil {
		return Recipe{}, err
	}
	return r, nil
}

// mintRecipeID generates a fresh 32-lowercase-hex recipe id.
func mintRecipeID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", wire.Errorf(wire.CodeInternal, "recipes: generate recipe id: %v", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// normalize puts the recipe in canonical form for encoding: reserved
// trigger maps are nilled when empty so nil and {} encode identically.
func (r *Recipe) normalize() {
	if len(r.Trigger.Watch) == 0 {
		r.Trigger.Watch = nil
	}
	if len(r.Trigger.Schedule) == 0 {
		r.Trigger.Schedule = nil
	}
}

// ScopeHash is the canonical SHA-256 identity of the recipe's material
// scope: sources, recipients, trigger kind, effective network policy,
// require-padding flag, include/exclude filters, expiry and budgets.
// Non-material fields (name, status, grant bookkeeping, timestamps,
// checksum) are excluded. Order-independent: sources sort by path,
// recipients by device id, filters lexicographically, so a semantically
// identical scope always hashes identically.
func (r Recipe) ScopeHash() string {
	h := newScopeHasher()
	srcs := append([]RecipeSource(nil), r.Sources...)
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].Path < srcs[j].Path })
	for _, s := range srcs {
		h.writeString("source")
		h.writeString(s.Path)
		h.writeBool(s.Recursive)
	}
	rcpts := append([]RecipeRecipient(nil), r.Recipients...)
	sort.Slice(rcpts, func(i, j int) bool { return rcpts[i].DeviceID < rcpts[j].DeviceID })
	for _, c := range rcpts {
		h.writeString("recipient")
		h.writeString(c.DeviceID)
		h.writeString(c.Label)
	}
	h.writeString("trigger")
	h.writeString(string(r.Trigger.Kind))
	if r.Trigger.Kind == TriggerWatch {
		// Watch configuration is material scope: changing debounce,
		// cooldown or recursion revokes the automation grant through the
		// normal ApplyUpdate material-change rule.
		h.writeString("triggerWatch")
		if wp, err := ParseWatchParams(r.Trigger.Watch); err == nil {
			h.writeInt64(wp.Debounce.Milliseconds())
			h.writeInt64(wp.Cooldown.Milliseconds())
			h.writeBool(wp.Recursive)
		} else {
			// An unvalidated record: validation rejects it, but the hash
			// must still be deterministic, so hash the raw map canonically.
			keys := make([]string, 0, len(r.Trigger.Watch))
			for k := range r.Trigger.Watch {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				h.writeString(k)
				h.writeString(fmt.Sprintf("%v", r.Trigger.Watch[k]))
			}
		}
	}
	p, err := netpolicy.Parse(r.NetworkPolicy)
	if err != nil {
		p = netpolicy.Online
	}
	h.writeString("networkPolicy")
	h.writeString(p.String())
	h.writeString("requirePadding")
	h.writeBool(r.RequirePadding)
	inc := append([]string(nil), r.Include...)
	sort.Strings(inc)
	for _, f := range inc {
		h.writeString("include")
		h.writeString(f)
	}
	exc := append([]string(nil), r.Exclude...)
	sort.Strings(exc)
	for _, f := range exc {
		h.writeString("exclude")
		h.writeString(f)
	}
	h.writeString("expiresAt")
	h.writeInt64(r.ExpiresAt.UTC().UnixNano())
	h.writeString("budgets")
	h.writeInt64(r.Budgets.MaxBytesPerRun)
	h.writeInt64(r.Budgets.MaxFilesPerRun)
	h.writeInt64(int64(r.Budgets.MaxConcurrentRuns))
	return h.sum()
}

// scopeHasher is a domain-separated incremental SHA-256 writer. Field
// values are length-framed so ("ab","c") and ("a","bc") can never collide.
type scopeHasher struct {
	h bytes.Buffer
}

func newScopeHasher() *scopeHasher {
	sh := &scopeHasher{}
	sh.h.Write([]byte("sendbeam/recipe-scope\x00"))
	return sh
}

func (sh *scopeHasher) writeString(s string) {
	var lb [8]byte
	binary.BigEndian.PutUint64(lb[:], uint64(len(s)))
	sh.h.Write(lb[:])
	sh.h.Write([]byte(s))
	sh.h.Write([]byte{0})
}

func (sh *scopeHasher) writeBool(b bool) {
	if b {
		sh.h.Write([]byte{1, 0})
	} else {
		sh.h.Write([]byte{0, 0})
	}
}

func (sh *scopeHasher) writeInt64(v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	sh.h.Write(b[:])
	sh.h.Write([]byte{0})
}

func (sh *scopeHasher) sum() string {
	sum := sha256.Sum256(sh.h.Bytes())
	return hex.EncodeToString(sum[:])
}

func isLowerHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isLowerHex32(s string) bool { return isLowerHexLen(s, 32) }

func isLowerHex64(s string) bool { return isLowerHexLen(s, 64) }

// ValidateRecipe checks structural invariants without touching the
// filesystem. It does not verify the checksum value (decode/seal do that);
// it does verify that an asserted AutoSend grant is actually backed by
// matching consent (non-zero GrantedAt, positive ConsentVersion, and a
// ScopeHash equal to the current material scope), so a grant can never be
// smuggled in or survive a scope change through the edit path.
func ValidateRecipe(r Recipe) error {
	return validateRecipe(r, true)
}

// validateRecipe is the shared validator. requireContent enforces the
// >= 1 sources / >= 1 recipients rule; NewRecipe passes false because a
// freshly constructed recipe is composed by the caller before it may be
// saved or dispatched.
func validateRecipe(r Recipe, requireContent bool) error {
	if r.SchemaVersion != RecipeSchemaVersion {
		return wire.Errorf(wire.CodeStorage, "recipes: unsupported schema version %d", r.SchemaVersion)
	}
	if !isLowerHex32(r.ID) {
		return wire.Errorf(wire.CodeStorage, "recipes: id must be 32 lowercase hex characters")
	}
	if strings.TrimSpace(r.Name) == "" {
		return wire.Errorf(wire.CodeStorage, "recipes: recipe name must not be empty")
	}
	switch r.Status {
	case RecipeDisabled, RecipeManual, RecipeApprovalRequired:
	default:
		return wire.Errorf(wire.CodeStorage, "recipes: unknown recipe status %q", r.Status)
	}
	if len(r.Sources) == 0 {
		if requireContent {
			return wire.Errorf(wire.CodeStorage, "recipes: recipe has no sources")
		}
	} else {
		for i, s := range r.Sources {
			if s.Path == "" {
				return wire.Errorf(wire.CodeStorage, "recipes: source %d has empty path", i)
			}
			if !filepath.IsAbs(s.Path) {
				return wire.Errorf(wire.CodeStorage, "recipes: source %d path %q is not absolute", i, s.Path)
			}
			if filepath.Clean(s.Path) != s.Path {
				return wire.Errorf(wire.CodeStorage, "recipes: source %d path %q is not clean (no \".\", \"..\" or redundant separators)", i, s.Path)
			}
		}
	}
	if len(r.Recipients) == 0 {
		if requireContent {
			return wire.Errorf(wire.CodeStorage, "recipes: recipe has no recipients")
		}
	} else {
		seen := make(map[string]bool, len(r.Recipients))
		for i, c := range r.Recipients {
			if !wire.ValidateDeviceID(c.DeviceID) {
				return wire.Errorf(wire.CodeStorage, "recipes: recipient %d has invalid device id %q", i, c.DeviceID)
			}
			if strings.TrimSpace(c.Label) == "" {
				return wire.Errorf(wire.CodeStorage, "recipes: recipient %d has empty label", i)
			}
			if seen[c.DeviceID] {
				return wire.Errorf(wire.CodeStorage, "recipes: duplicate recipient device %q", c.DeviceID)
			}
			seen[c.DeviceID] = true
		}
	}
	if _, err := netpolicy.Parse(r.NetworkPolicy); err != nil {
		return wire.Errorf(wire.CodeStorage, "recipes: invalid networkPolicy %q", r.NetworkPolicy)
	}
	switch r.Trigger.Kind {
	case TriggerManual, TriggerWatch, TriggerSchedule:
	default:
		return wire.Errorf(wire.CodeStorage, "recipes: unknown trigger kind %q", r.Trigger.Kind)
	}
	// Watch parameters are validated when the trigger kind is "watch"; a
	// non-empty watch map on any other kind is meaningless and rejected
	// fail-closed. Schedule detail is still reserved (V22-PR05): its map
	// must be empty.
	if r.Trigger.Kind == TriggerWatch {
		if _, err := ParseWatchParams(r.Trigger.Watch); err != nil {
			return err
		}
	} else if len(r.Trigger.Watch) > 0 {
		return wire.Errorf(wire.CodeStorage,
			"recipes: trigger.watch parameters require trigger kind \"watch\", got %q", r.Trigger.Kind)
	}
	if len(r.Trigger.Schedule) > 0 {
		return wire.Errorf(wire.CodeStorage, "recipes: trigger.schedule parameters are not supported in schema version 1 (schedule detail lands in a later PR)")
	}
	if r.Budgets.MaxBytesPerRun <= 0 || r.Budgets.MaxFilesPerRun <= 0 || r.Budgets.MaxConcurrentRuns <= 0 {
		return wire.Errorf(wire.CodeStorage, "recipes: budgets must all be > 0 (use DefaultBudgets for the conservative defaults)")
	}
	if r.Grant.AutoSend {
		if r.Grant.GrantedAt.IsZero() {
			return wire.Errorf(wire.CodeStorage, "recipes: autoSend grant without grantedAt")
		}
		if r.Grant.ConsentVersion <= 0 {
			return wire.Errorf(wire.CodeStorage, "recipes: autoSend grant without a positive consent version")
		}
		if r.Grant.ScopeHash == "" || r.Grant.ScopeHash != r.ScopeHash() {
			return wire.Errorf(wire.CodeStorage, "recipes: autoSend grant scope hash does not match the current material scope (re-approval required)")
		}
	}
	return nil
}

// GrantValid reports whether the recipe's automation grant currently
// authorizes automated (non-manual) dispatch: AutoSend must be on, the
// consent must be timestamped and versioned, and the scope hash must match
// the recipe's current material scope. A grant dated in the future (clock
// skew or hand-edited record) is invalid. Any material change revokes the
// grant via ApplyUpdate (AutoSend cleared, ConsentVersion bumped), so a
// stale grant can never validate afterwards.
func (r Recipe) GrantValid(now time.Time) bool {
	g := r.Grant
	if !g.AutoSend || g.ConsentVersion <= 0 || g.GrantedAt.IsZero() {
		return false
	}
	if g.ScopeHash == "" || g.ScopeHash != r.ScopeHash() {
		return false
	}
	if g.GrantedAt.After(now.UTC()) {
		return false
	}
	return true
}

// GrantAutomation records explicit user consent for automatic dispatch of
// r: it sets AutoSend, timestamps the consent, binds it to the recipe's
// current material scope, and keeps the current consent version (starting
// one when no version was ever recorded). The status is left untouched —
// granting is only meaningful on a "manual" recipe, so approval-required
// and disabled recipes are refused with an actionable error. Granting
// never runs anything: grant != run. Any later material change revokes
// this consent (see ApplyUpdate) and the user must re-grant explicitly.
//
// The caller persists the returned recipe (store.Save).
func GrantAutomation(r *Recipe, now time.Time) error {
	if r == nil {
		return wire.Errorf(wire.CodeInternal, "recipes: nil recipe")
	}
	switch r.Status {
	case RecipeManual:
		// The only status automated dispatch may run under.
	case RecipeDisabled:
		return wire.Errorf(wire.CodeAuth,
			"recipes: cannot grant auto-send on disabled recipe %q — enable it before granting", r.Name)
	case RecipeApprovalRequired:
		return wire.Errorf(wire.CodeAuth,
			"recipes: recipe %q requires approval before auto-send can be granted — run `recipe approve %s` first", r.Name, r.ID)
	default:
		return wire.Errorf(wire.CodeStorage, "recipes: recipe %q has unknown status %q", r.Name, r.Status)
	}
	cv := r.Grant.ConsentVersion
	if cv <= 0 {
		cv = 1
	}
	r.Grant = RecipeGrant{
		AutoSend:       true,
		ConsentVersion: cv,
		GrantedAt:      now.UTC(),
		ScopeHash:      r.ScopeHash(),
	}
	return nil
}

// RevokeAutomation withdraws the auto-send consent on r: AutoSend and the
// grant timestamp are cleared (the scope hash is cleared too, so a later
// refusal names the absence of a grant rather than a stale scope). The
// consent version and the status are left untouched — revoking never
// changes what the recipe is, only whether it may dispatch automatically.
// Manual runs remain allowed.
//
// The caller persists the recipe (store.Save).
func RevokeAutomation(r *Recipe) {
	if r == nil {
		return
	}
	r.Grant.AutoSend = false
	r.Grant.GrantedAt = time.Time{}
	r.Grant.ScopeHash = ""
}

// ApplyUpdate applies an edited recipe through the store, enforcing the
// material-change rule: if the material scope (ScopeHash) changed since the
// stored version, any automation consent is revoked — ConsentVersion is
// bumped, AutoSend is cleared, GrantedAt is zeroed, and the status is
// forced to "approval-required" so a person re-reviews before anything
// dispatches. A stored "disabled" recipe stays "disabled": a material
// change must never broaden a recipe the user explicitly switched off.
// Non-material edits (e.g. rename) keep the stored grant untouched — the
// caller's grant fields are ignored and replaced with the stored grant, so
// a grant can never be smuggled in through the edit path. The grant's
// ScopeHash is refreshed to the current scope on every update.
//
// The grant is reconciled before validation: the caller's grant fields are
// never trusted, so a material edit on a granted recipe revokes the grant
// instead of failing validation on the now-stale consent.
//
// The returned recipe is the freshly stored record.
func ApplyUpdate(store *RecipeStore, updated Recipe) (Recipe, error) {
	if store == nil {
		return Recipe{}, wire.Errorf(wire.CodeInternal, "recipes: nil recipe store")
	}
	if !isLowerHex32(updated.ID) {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: invalid recipe id %q", updated.ID)
	}
	stored, ok, err := store.Load(updated.ID)
	if err != nil {
		return Recipe{}, err
	}
	if !ok {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: cannot update unknown recipe %q", updated.ID)
	}
	// Reconcile the grant BEFORE validating: the caller's grant fields are
	// never trusted (see below), and a material change on a granted recipe
	// must revoke the grant — not fail validation because the stored
	// consent no longer matches the edited scope. Validating first would
	// reject the edit instead of revoking, which contradicts the
	// material-change rule.
	newScope := updated.ScopeHash()
	if newScope != stored.ScopeHash() {
		// Material change: revoke automation consent.
		updated.Grant = RecipeGrant{
			AutoSend:       false,
			ConsentVersion: stored.Grant.ConsentVersion + 1,
			ScopeHash:      newScope,
		}
		if stored.Status == RecipeDisabled {
			updated.Status = RecipeDisabled
		} else {
			updated.Status = RecipeApprovalRequired
		}
	} else {
		// Non-material edit: the stored grant carries over verbatim.
		updated.Grant = stored.Grant
		updated.Grant.ScopeHash = newScope
	}
	if err := ValidateRecipe(updated); err != nil {
		return Recipe{}, err
	}
	if err := store.Save(updated); err != nil {
		return Recipe{}, err
	}
	saved, ok, err := store.Load(updated.ID)
	if err != nil {
		return Recipe{}, err
	}
	if !ok {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: recipe %q vanished after save", updated.ID)
	}
	return saved, nil
}

// ValidateRecipients checks every recipient against the current trust
// store: each device id must be a known, non-revoked trusted device.
// Revocation or unpairing after the recipe was written fails closed here,
// naming the offending device. This is a point-in-time check — dispatch
// revalidates at enqueue/send time because trust can change.
func ValidateRecipients(ctx context.Context, ts trust.Store, r Recipe) error {
	if ts == nil {
		return wire.Errorf(wire.CodeInternal, "recipes: nil trust store")
	}
	for _, c := range r.Recipients {
		rec, err := ts.GetDevice(ctx, c.DeviceID)
		if err != nil {
			return wire.Errorf(wire.CodeAuth,
				"recipes: recipient %q (%s) is not a currently trusted device: %v", c.Label, c.DeviceID, err)
		}
		if rec.Revoked {
			return wire.Errorf(wire.CodeAuth,
				"recipes: recipient %q (%s) has been revoked and cannot receive recipe runs", c.Label, c.DeviceID)
		}
	}
	return nil
}
