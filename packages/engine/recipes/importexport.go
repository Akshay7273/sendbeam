// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"time"
)

// Export serializes a recipe to its canonical JSON encoding. The schema
// contains no key material, credentials or reusable secrets by design —
// recipients are named by device id (public identity) and the destination
// is receiver-approved policy, so the export is safe to copy, back up or
// share for review. The recipe id is preserved.
func Export(r Recipe) ([]byte, error) {
	if err := ValidateRecipe(r); err != nil {
		return nil, err
	}
	return encodeRecipe(r)
}

// Import reads canonical recipe JSON and returns a recipe that NEVER runs
// automatically: the status is forced to "disabled", any AutoSend grant is
// cleared and GrantedAt is zeroed. Consent never transfers — automation
// must be re-approved explicitly after import. The id is kept only if it
// is a valid 32-lowercase-hex id; otherwise a fresh one is minted so a
// malformed import can never collide with or shadow an existing recipe.
//
// Import validates the input strictly (schema version, checksum, full
// structure) and fails closed on anything unexpected.
func Import(data []byte) (Recipe, error) {
	r, err := decodeRecipe(data)
	if err != nil {
		return Recipe{}, err
	}
	if !isLowerHex32(r.ID) {
		// Unreachable for strict-decoded recipes today (ValidateRecipe
		// requires it), but stated explicitly: an import must never
		// produce a recipe with an invalid id.
		r.ID, err = mintRecipeID()
		if err != nil {
			return Recipe{}, err
		}
	}
	r.Status = RecipeDisabled
	r.Grant.AutoSend = false
	r.Grant.GrantedAt = time.Time{}
	r.Grant.ScopeHash = r.ScopeHash()
	// The last-run ledger and the schedule cursor are host-local history:
	// an imported recipe starts with no runs recorded here and adopts a
	// fresh cursor on its first scheduler tick.
	r.LastRun = nil
	r.ScheduleCursor = nil
	sealed, err := sealRecipe(r)
	if err != nil {
		return Recipe{}, err
	}
	return sealed, nil
}
