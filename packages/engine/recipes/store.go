// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

// recipesDirEnv overrides the recipes directory (tests).
const recipesDirEnv = "SENDBEAM_RECIPES_DIR"

// RecipeStoreDir resolves the recipes directory: SENDBEAM_RECIPES_DIR if
// set, else os.UserConfigDir()/sendbeam/recipes. Resolution failure fails
// closed.
func RecipeStoreDir() (string, error) {
	if dir := os.Getenv(recipesDirEnv); dir != "" {
		return filepath.Abs(dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", wire.Errorf(wire.CodeStorage, "recipes: resolve config dir: %v", err)
	}
	return filepath.Join(base, "sendbeam", "recipes"), nil
}

// RecipeStore owns the recipes directory: recipe load/save with atomic
// replace, listing, explicit deletion, and quarantine surfacing. Quarantine
// entries are never deleted and never guessed at — the operator renames or
// removes them by hand after review.
type RecipeStore struct {
	dir string
	// now is the clock for timestamps; tests inject a fixed one.
	now func() time.Time
	// write writes a recipe atomically; tests inject failures (no sleeps).
	write func(path string, r Recipe) error
}

// OpenRecipeStore prepares (creating if needed) the recipes directory and
// resolves it absolutely so a later chdir cannot redirect writes.
func OpenRecipeStore(dir string) (*RecipeStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: resolve recipes dir: %v", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: create %s: %v", abs, err)
	}
	return &RecipeStore{
		dir:   abs,
		now:   time.Now,
		write: writeRecipeAtomic,
	}, nil
}

// Dir returns the resolved absolute recipes directory.
func (s *RecipeStore) Dir() string { return s.dir }

// Path returns the recipe file path for one recipe id.
func (s *RecipeStore) Path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

// Load reads, decodes, validates, and checksum-verifies the recipe. It
// returns (recipe, false, nil) when no recipe exists, and fails closed
// (error) when the file exists but is corrupt, torn, tampered, or from an
// unsupported schema version. Nothing is deleted on a load error — the
// caller surfaces the file via Quarantined().
func (s *RecipeStore) Load(id string) (Recipe, bool, error) {
	if !isLowerHex32(id) {
		return Recipe{}, false, wire.Errorf(wire.CodeStorage, "recipes: invalid recipe id %q", id)
	}
	r, err := s.loadFile(s.Path(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Recipe{}, false, nil
		}
		return Recipe{}, true, err
	}
	if r.ID != id {
		return Recipe{}, true, wire.Errorf(wire.CodeStorage,
			"recipes: recipe id mismatch: file %q holds %q (corrupt or tampered)", id, r.ID)
	}
	return r, true, nil
}

// Save validates and writes a recipe atomically through the configured
// writer. Save does not apply the material-change rule — use ApplyUpdate
// for user edits so automation consent is revoked correctly. The checksum
// is recomputed over the canonical encoding.
func (s *RecipeStore) Save(r Recipe) error {
	r.UpdatedAt = s.now().UTC()
	return s.write(s.Path(r.ID), r)
}

// RecordRun replaces the recipe's LastRun ledger entry and saves it
// through the normal validated path (UpdatedAt refreshed, checksum
// recomputed). It loads the current record first so concurrent writers
// only ever replace the ledger entry, never the recipe itself.
func (s *RecipeStore) RecordRun(recipeID string, info RecipeRunInfo) error {
	r, ok, err := s.Load(recipeID)
	if err != nil {
		return err
	}
	if !ok {
		return wire.Errorf(wire.CodeStorage, "recipes: no recipe %q", recipeID)
	}
	if info.At.IsZero() {
		info.At = s.now().UTC()
	} else {
		info.At = info.At.UTC()
	}
	r.LastRun = &info
	return s.Save(r)
}

// Delete removes one recipe, idempotently and bounded to that recipe: it
// never touches other recipes. Only explicit user action calls this.
func (s *RecipeStore) Delete(id string) error {
	if !isLowerHex32(id) {
		return wire.Errorf(wire.CodeStorage, "recipes: invalid recipe id %q", id)
	}
	if err := os.Remove(s.Path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return wire.Errorf(wire.CodeStorage, "recipes: delete recipe: %v", err)
	}
	return nil
}

// RecipeEntry is a list-view summary of one stored recipe.
type RecipeEntry struct {
	ID             string
	Name           string
	Status         RecipeStatus
	Trigger        string
	Sources        int
	Recipients     int
	AutoSend       bool
	ConsentVersion int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// List returns every loadable recipe. Files that fail to load (unknown
// schema version, corrupt JSON, checksum mismatch) are NOT returned here;
// they are surfaced via Quarantined() and never deleted.
func (s *RecipeStore) List() ([]RecipeEntry, error) {
	files, err := s.scan()
	if err != nil {
		return nil, err
	}
	var out []RecipeEntry
	for _, f := range files {
		if f.err != nil {
			continue
		}
		r := f.recipe
		out = append(out, RecipeEntry{
			ID:             r.ID,
			Name:           r.Name,
			Status:         r.Status,
			Trigger:        string(r.Trigger.Kind),
			Sources:        len(r.Sources),
			Recipients:     len(r.Recipients),
			AutoSend:       r.Grant.AutoSend,
			ConsentVersion: r.Grant.ConsentVersion,
			CreatedAt:      r.CreatedAt,
			UpdatedAt:      r.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// QuarantineEntry describes one recipe file that could not be loaded:
// unknown schema version, corrupt JSON, checksum mismatch, or an id that
// does not match the file name. The file is left in place, untouched.
type QuarantineEntry struct {
	Path   string
	Reason string
}

// Quarantined scans the store and returns every file that cannot be loaded
// as a recipe, with the reason. Nothing is deleted or modified.
func (s *RecipeStore) Quarantined() ([]QuarantineEntry, error) {
	files, err := s.scan()
	if err != nil {
		return nil, err
	}
	var out []QuarantineEntry
	for _, f := range files {
		if f.err == nil {
			continue
		}
		out = append(out, QuarantineEntry{Path: f.path, Reason: f.err.Error()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// scanFile is one scanned store file: either a decoded recipe or the load
// error that quarantines it.
type scanFile struct {
	path   string
	recipe Recipe
	err    error
}

// scan reads and decodes every *.json file in the store directory. A
// single bad file never hides the others and is never deleted.
func (s *RecipeStore) scan() ([]scanFile, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "recipes: list %s: %v", s.dir, err)
	}
	var out []scanFile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		path := filepath.Join(s.dir, entry.Name())
		if id == "" || !isLowerHex32(id) {
			out = append(out, scanFile{path: path, err: wire.Errorf(wire.CodeStorage,
				"recipes: invalid recipe file name %q (quarantined; refusing to read)", entry.Name())})
			continue
		}
		r, err := s.loadFile(path)
		if err != nil {
			out = append(out, scanFile{path: path, err: err})
			continue
		}
		if r.ID != id {
			out = append(out, scanFile{path: path, err: wire.Errorf(wire.CodeStorage,
				"recipes: recipe id mismatch: file %q holds %q (corrupt or tampered; quarantined)", entry.Name(), r.ID)})
			continue
		}
		out = append(out, scanFile{path: path, recipe: r})
	}
	return out, nil
}

// loadFile reads and fully verifies one recipe file: strict schema,
// supported version, checksum over the canonical encoding, and structural
// validation. os.ErrNotExist propagates so Load can report absence.
func (s *RecipeStore) loadFile(path string) (Recipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Recipe{}, err
	}
	return decodeRecipe(data)
}

// sealRecipe validates a recipe and returns it with the checksum computed
// over the canonical encoding of every other field.
func sealRecipe(r Recipe) (Recipe, error) {
	r.normalize()
	if err := ValidateRecipe(r); err != nil {
		return Recipe{}, err
	}
	r.Checksum = ""
	body, err := marshalRecipeJSON(r)
	if err != nil {
		return Recipe{}, err
	}
	sum := sha256.Sum256(body)
	r.Checksum = hex.EncodeToString(sum[:])
	if err := ValidateRecipe(r); err != nil {
		return Recipe{}, err
	}
	return r, nil
}

// encodeRecipe produces the canonical file encoding: the checksum covers
// the exact bytes of every other field.
func encodeRecipe(r Recipe) ([]byte, error) {
	sealed, err := sealRecipe(r)
	if err != nil {
		return nil, err
	}
	return marshalRecipeJSON(sealed)
}

// decodeRecipe parses and verifies a stored recipe: strict schema,
// supported version, checksum over the exact body, and full structural
// validation. Schema versions other than the current one fail closed
// (quarantined, never migrated silently). A recipe whose budgets are
// entirely absent gets the conservative defaults — this is the only
// fill-in decodeRecipe performs, and defaults are inert (no grant).
func decodeRecipe(data []byte) (Recipe, error) {
	// Peek the schema version with a lenient decoder (the strict decoder
	// below would reject an unknown-version document for the wrong
	// reason, or misread it entirely).
	var head struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&head); err != nil {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: malformed recipe: %v", err)
	}
	if head.SchemaVersion != RecipeSchemaVersion {
		return Recipe{}, wire.Errorf(wire.CodeStorage,
			"recipes: unsupported recipe schema version %d (quarantined; refusing to read)", head.SchemaVersion)
	}
	var r Recipe
	if err := unmarshalStrictRecipe(data, &r); err != nil {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: decode recipe: %v", err)
	}
	stored := r.Checksum
	if !isLowerHex64(stored) {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: malformed checksum")
	}
	r.Checksum = ""
	r.normalize()
	body, err := marshalRecipeJSON(r)
	if err != nil {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: re-encode recipe: %v", err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != stored {
		return Recipe{}, wire.Errorf(wire.CodeStorage, "recipes: checksum mismatch (corrupt or tampered)")
	}
	r.Checksum = stored
	if r.Budgets.MaxBytesPerRun == 0 && r.Budgets.MaxFilesPerRun == 0 && r.Budgets.MaxConcurrentRuns == 0 {
		r.Budgets = DefaultBudgets()
	}
	if err := ValidateRecipe(r); err != nil {
		return Recipe{}, err
	}
	return r, nil
}

// marshalRecipeJSON encodes with no HTML escaping and no trailing newline,
// so the encoding is byte-identical to the jobs/journal conventions.
func marshalRecipeJSON(r Recipe) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// unmarshalStrictRecipe decodes exactly one JSON value, rejecting unknown
// fields and trailing data so an unexpected field or a torn tail fails
// closed.
func unmarshalStrictRecipe(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// writeRecipeAtomic writes the canonical encoding through the
// atomic-replacement primitive: a temp file in the same directory,
// fsynced, closed, then renamed over the recipe, so a crash leaves either
// the old recipe or the complete new one. The temp file inherits
// CreateTemp's 0600 mode; the parent dir is fsynced afterwards (best
// effort).
func writeRecipeAtomic(path string, r Recipe) error {
	data, err := encodeRecipe(r)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return wire.Errorf(wire.CodeStorage, "recipes: create temp: %v", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "recipes: write temp: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "recipes: sync temp: %v", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "recipes: close temp: %v", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return wire.Errorf(wire.CodeStorage, "recipes: replace: %v", err)
	}
	syncRecipesDir(dir)
	return nil
}

// syncRecipesDir fsyncs a directory so a rename inside it is durable.
// POSIX only; filesystems that reject directory sync are best-effort.
func syncRecipesDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}
