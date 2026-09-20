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
// truncating them. Watch/schedule trigger detail lands in a later PR with
// a schema bump if the wire shape has to change.
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

// Trigger kinds. "watch" and "schedule" detail lands in V22-PR04/PR05;
// until then their reserved parameter maps must be empty (PR01).
const (
	TriggerManual   = "manual"
	TriggerWatch    = "watch"
	TriggerSchedule = "schedule"
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

// RecipeTrigger describes what may start a run. Watch and Schedule are
// reserved parameter maps for V22-PR04/PR05; they MUST be empty in PR01
// and validation rejects non-empty maps.
type RecipeTrigger struct {
	Kind     string         `json:"kind"`
	Watch    map[string]any `json:"watch,omitempty"`
	Schedule map[string]any `json:"schedule,omitempty"`
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
	h.writeString(r.Trigger.Kind)
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
	// PR01: watch/schedule detail is not designed yet; the reserved maps
	// must be empty so no unreviewed trigger semantics can sneak in.
	if len(r.Trigger.Watch) > 0 {
		return wire.Errorf(wire.CodeStorage, "recipes: trigger.watch parameters are not supported in schema version 1 (watch detail lands in a later PR)")
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
	if err := ValidateRecipe(updated); err != nil {
		return Recipe{}, err
	}
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
