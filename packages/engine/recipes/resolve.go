// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sendbeam/wire"
)

// PlanFile is one file matched by a recipe resolution: its absolute path,
// size in bytes, and SHA-256 hex digest of its content at resolve time.
// Digests are of the file content only (not names or metadata) so the
// transfer layer can verify content integrity.
type PlanFile struct {
	Path   string
	Size   int64
	Digest string
}

// Plan is the fully resolved, secrets-free execution plan for a recipe:
// the file set that would be sent right now, the total byte budget, the
// recipients, and any warnings (e.g. skipped symlinks). A plan is a
// dry-run artifact: it never creates jobs and causes no remote effects.
type Plan struct {
	RecipeID       string
	RecipeName     string
	Files          []PlanFile
	TotalBytes     int64
	Recipients     []RecipeRecipient
	NetworkPolicy  string
	RequirePadding bool
	Warnings       []string
	ResolvedAt     time.Time
}

// ResolveOptions tunes Resolve; the zero value resolves recursively with
// no filters.
type ResolveOptions struct {
	// Now is the clock for ResolvedAt; defaults to time.Now().UTC().
	Now func() time.Time
	// FollowDirSymlinks, when true, descends into symlinked directories
	// (still confined within the resolved source root). When false,
	// symlinked directories are skipped (not descended). File symlinks
	// are always read through their resolved target but must stay within
	// the resolved source root.
	FollowDirSymlinks bool
}

// Resolve walks each recipe source root and builds the concrete file plan.
//
//   - A source that is a file becomes a single entry; a source that is a
//     directory is walked. Recursive=false reads only the top level of a
//     directory source.
//   - Include globs act as an allow-list (empty = everything allowed);
//     Exclude globs remove matches. Globs follow path/filepath.Match
//     against the path RELATIVE to the source root, using forward slashes
//     (e.g. "*.log" matches only top-level *.log; "docs/*.pdf" matches
//     under docs/). There is NO "**" support in v1: a pattern containing
//     "**" is rejected as invalid rather than half-interpreted.
//   - Symlink escape protection: every candidate file path is resolved
//     with filepath.EvalSymlinks and MUST land within the resolved source
//     root. A candidate that escapes is skipped and recorded in
//     Plan.Warnings (deterministic, sorted). Files outside the source
//     root are never read.
//   - Unreadable files (permission denied on open/read/stat) are hard
//     errors naming the path: a plan must never silently drop data.
//   - Directories themselves never become plan entries; files sort by
//     path so a plan is deterministic for a given tree.
//   - Digest is SHA-256 of the file content read at resolve time.
//
// Only local reads happen here: no job creation, no network, no writes.
func Resolve(r Recipe, opts ResolveOptions) (Plan, error) {
	now := time.Now().UTC
	if opts.Now != nil {
		now = opts.Now
	}
	if err := validateRecipe(r, true); err != nil {
		return Plan{}, err
	}
	for _, g := range append(append([]string{}, r.Include...), r.Exclude...) {
		if strings.Contains(g, "**") {
			return Plan{}, wire.Errorf(wire.CodeStorage,
				"recipes: glob %q uses \"**\", which is not supported in schema version 1 (no recursive wildcard)", g)
		}
		if _, err := filepath.Match(g, "probe"); err != nil {
			return Plan{}, wire.Errorf(wire.CodeStorage, "recipes: invalid glob %q: %v", g, err)
		}
	}

	plan := Plan{
		RecipeID:       r.ID,
		RecipeName:     r.Name,
		Recipients:     append([]RecipeRecipient(nil), r.Recipients...),
		NetworkPolicy:  effectivePolicyName(r),
		RequirePadding: r.RequirePadding,
		ResolvedAt:     now().UTC(),
	}
	seen := make(map[string]bool)
	for _, src := range r.Sources {
		files, warnings, err := resolveSource(src, r.Include, r.Exclude, opts.FollowDirSymlinks)
		if err != nil {
			return Plan{}, err
		}
		plan.Warnings = append(plan.Warnings, warnings...)
		for _, f := range files {
			if seen[f.Path] {
				continue // overlapping roots resolve the same file once
			}
			seen[f.Path] = true
			plan.Files = append(plan.Files, f)
			plan.TotalBytes += f.Size
		}
	}
	sort.Slice(plan.Files, func(i, j int) bool { return plan.Files[i].Path < plan.Files[j].Path })
	sort.Strings(plan.Warnings)
	return plan, nil
}

// resolveSource expands one recipe source root into plan files.
func resolveSource(src RecipeSource, include, exclude []string, followDirSymlinks bool) ([]PlanFile, []string, error) {
	rootAbs, err := filepath.Abs(src.Path)
	if err != nil {
		return nil, nil, wire.Errorf(wire.CodeSourceIO, "recipes: resolve source root %q: %v", src.Path, err)
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return nil, nil, wire.Errorf(wire.CodeSourceIO, "recipes: source root %q is not accessible: %v", src.Path, err)
	}
	var warnings []string
	var files []PlanFile
	add := func(absPath string) error {
		resolved, ok, err := confineToRoot(absPath, rootResolved)
		if err != nil {
			return err
		}
		if !ok {
			warnings = append(warnings, "skipped symlink escaping its source root: "+absPath)
			return nil
		}
		info, err := os.Stat(resolved)
		if err != nil {
			if os.IsPermission(err) {
				return wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading %q", absPath)
			}
			return wire.Errorf(wire.CodeSourceIO, "recipes: cannot stat %q: %v", absPath, err)
		}
		if info.IsDir() {
			return nil // directories are traversed, never entries
		}
		if !matchFilters(absPath, rootAbs, include, exclude) {
			return nil
		}
		digest, size, err := digestFile(resolved)
		if err != nil {
			return err
		}
		files = append(files, PlanFile{Path: absPath, Size: size, Digest: digest})
		return nil
	}

	info, err := os.Stat(rootResolved)
	if err != nil {
		return nil, nil, wire.Errorf(wire.CodeSourceIO, "recipes: source root %q is not accessible: %v", src.Path, err)
	}
	if !info.IsDir() {
		// A file source is one entry; it must still match the filters.
		if err := add(rootAbs); err != nil {
			return nil, nil, err
		}
		return files, warnings, nil
	}

	if !src.Recursive {
		entries, err := os.ReadDir(rootResolved)
		if err != nil {
			return nil, nil, wire.Errorf(wire.CodeSourceIO, "recipes: cannot read source directory %q: %v", src.Path, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if err := add(filepath.Join(rootAbs, e.Name())); err != nil {
				return nil, nil, err
			}
		}
		return files, warnings, nil
	}

	w := &sourceWalker{
		rootResolved:      rootResolved,
		followDirSymlinks: followDirSymlinks,
		add:               add,
		addWarning:        func(warn string) { warnings = append(warnings, warn) },
	}
	if err := w.walkDir(rootAbs, rootResolved); err != nil {
		return nil, nil, err
	}
	return files, warnings, nil
}

// sourceWalker recursively walks a source root in user-visible
// (unresolved) path space while traversing the resolved filesystem tree,
// so plans report the paths the user configured while confinement is
// always checked against fully resolved targets.
type sourceWalker struct {
	rootResolved      string
	followDirSymlinks bool
	add               func(absPath string) error
	addWarning        func(warn string)
}

func (w *sourceWalker) walkDir(userDir, resolvedDir string) error {
	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		if os.IsPermission(err) {
			return wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading directory %q", userDir)
		}
		return wire.Errorf(wire.CodeSourceIO, "recipes: cannot read directory %q: %v", userDir, err)
	}
	for _, e := range entries {
		userPath := filepath.Join(userDir, e.Name())
		resolvedPath := filepath.Join(resolvedDir, e.Name())
		linfo, err := os.Lstat(resolvedPath)
		if err != nil {
			if os.IsPermission(err) {
				return wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading %q", userPath)
			}
			return wire.Errorf(wire.CodeSourceIO, "recipes: cannot stat %q: %v", userPath, err)
		}
		if linfo.Mode()&os.ModeSymlink != 0 {
			target, serr := os.Stat(resolvedPath)
			if serr != nil {
				return wire.Errorf(wire.CodeSourceIO, "recipes: cannot resolve symlink %q: %v", userPath, serr)
			}
			if target.IsDir() {
				if !w.followDirSymlinks {
					continue
				}
				targetResolved, serr := filepath.EvalSymlinks(resolvedPath)
				if serr != nil {
					return wire.Errorf(wire.CodeSourceIO, "recipes: cannot resolve symlink %q: %v", userPath, serr)
				}
				if !withinRoot(targetResolved, w.rootResolved) {
					// Never descend into an escaped tree: the root itself
					// is the boundary, and reading outside it would violate
					// the "authorized roots" guarantee.
					w.addWarning("skipped symlink escaping its source root: " + userPath)
					continue
				}
				if err := w.walkDir(userPath, targetResolved); err != nil {
					return err
				}
				continue
			}
			// File symlink: add() reads through the target but enforces
			// confinement (escape → warning, not descent).
			if err := w.add(userPath); err != nil {
				return err
			}
			continue
		}
		if e.IsDir() {
			if err := w.walkDir(userPath, resolvedPath); err != nil {
				return err
			}
			continue
		}
		if err := w.add(userPath); err != nil {
			return err
		}
	}
	return nil
}

// withinRoot reports whether resolved is inside root (root itself counts).
func withinRoot(resolved, root string) bool {
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// confineToRoot resolves absPath through symlinks and reports whether it
// stays within root. A path that cannot be evaluated is a hard error.
func confineToRoot(absPath, root string) (resolved string, ok bool, err error) {
	resolved, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		if os.IsPermission(err) {
			return "", false, wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading %q", absPath)
		}
		return "", false, wire.Errorf(wire.CodeSourceIO, "recipes: cannot resolve %q: %v", absPath, err)
	}
	if !withinRoot(resolved, root) {
		return "", false, nil
	}
	return resolved, true, nil
}

// matchFilters applies include/exclude globs against the path relative to
// the source root, with separators normalized to forward slashes so
// patterns behave identically across platforms.
func matchFilters(absPath, rootAbs string, include, exclude []string) bool {
	rel, err := filepath.Rel(rootAbs, absPath)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if len(include) > 0 {
		matched := false
		for _, g := range include {
			if ok, _ := filepath.Match(g, rel); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, g := range exclude {
		if ok, _ := filepath.Match(g, rel); ok {
			return false
		}
	}
	return true
}

// digestFile returns the SHA-256 hex digest and size of a file's content.
func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return "", 0, wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading %q", path)
		}
		return "", 0, wire.Errorf(wire.CodeSourceIO, "recipes: cannot open %q: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		if os.IsPermission(err) {
			return "", 0, wire.Errorf(wire.CodeSourceIO, "recipes: permission denied reading %q", path)
		}
		return "", 0, wire.Errorf(wire.CodeSourceIO, "recipes: cannot read %q: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// planDTOVersion is the public versioned contract of PlanDTO. Additive
// fields only: consumers must ignore unknown fields.
const planDTOVersion = 1

type planFileDTO struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}

type planRecipientDTO struct {
	DeviceID string `json:"deviceId"`
	Label    string `json:"label"`
}

// PlanDTO encodes a plan as versioned machine-readable JSON. This is the
// v1 public DTO contract: additive changes only, and secret-free by
// construction — there are no secret fields anywhere in the recipe domain,
// so nothing in the DTO can leak key material. Labels, paths and device
// ids are operational identifiers, not credentials; consumer tests should
// still assert the absence of key material for tricky labels.
func PlanDTO(p Plan) []byte {
	files := make([]planFileDTO, len(p.Files))
	for i, f := range p.Files {
		files[i] = planFileDTO(f)
	}
	recipients := make([]planRecipientDTO, len(p.Recipients))
	for i, c := range p.Recipients {
		recipients[i] = planRecipientDTO(c)
	}
	warnings := p.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	dto := struct {
		Version        int                `json:"version"`
		RecipeID       string             `json:"recipeId"`
		RecipeName     string             `json:"recipeName"`
		Status         string             `json:"status"`
		Files          []planFileDTO      `json:"files"`
		TotalBytes     int64              `json:"totalBytes"`
		Recipients     []planRecipientDTO `json:"recipients"`
		NetworkPolicy  string             `json:"networkPolicy"`
		RequirePadding bool               `json:"requirePadding"`
		Warnings       []string           `json:"warnings"`
		ResolvedAt     string             `json:"resolvedAt"`
	}{
		Version:        planDTOVersion,
		RecipeID:       p.RecipeID,
		RecipeName:     p.RecipeName,
		Status:         "dry-run",
		Files:          files,
		TotalBytes:     p.TotalBytes,
		Recipients:     recipients,
		NetworkPolicy:  p.NetworkPolicy,
		RequirePadding: p.RequirePadding,
		Warnings:       warnings,
		ResolvedAt:     p.ResolvedAt.UTC().Format(time.RFC3339),
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(dto); err != nil {
		// Struct encoding cannot fail for these field types; encode
		// deterministically rather than returning an error contract.
		panic("recipes: plan DTO encode: " + err.Error())
	}
	out := buf.Bytes()
	return out[:len(out)-1] // trim trailing newline
}
