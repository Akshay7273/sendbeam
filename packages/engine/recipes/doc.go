// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

// Package recipes implements SendBeam v2.2 "Repeatable Handoffs" saved
// handoff recipes (V22-PR01, ADR 0012).
//
// A recipe is a small, local, reviewable workflow model: explicit local
// source roots, fixed authenticated recipients, an allowed network/privacy
// mode, file filters, a trigger kind, an expiry and resource budgets. The
// destination is always receiver-approved policy — a recipe can never grant
// the sender the right to choose arbitrary remote paths, and it never
// embeds secrets or reusable credentials (there are no secret fields in the
// schema by design).
//
// The automation model separates three things that must not be confused:
//
//   - one-shot manual runs (V22-PR02): never need a grant;
//   - the sender-side auto-dispatch grant (RecipeGrant.AutoSend): an explicit
//     opt-in recorded here, invalidated by any material scope change;
//   - receiver auto-acceptance: lives on the receiver side in its trust
//     policy, not in this schema; neither implies the other.
//
// New, imported and materially changed recipes never run automatically:
// they default to (or are forced back to) "approval-required" — or stay
// "disabled" if they were disabled — and any AutoSend grant is revoked
// when the material scope (sources, recipients, trigger, network policy,
// padding, filters, expiry, budgets) changes. See ApplyUpdate and the ADR
// for the exact consent-invalidation rule.
//
// Storage mirrors the v2.0 jobs store: one canonical JSON file per recipe
// under <os.UserConfigDir>/sendbeam/recipes (SENDBEAM_RECIPES_DIR overrides
// it for tests), 0600 atomic writes, strict decoding, checksums over the
// canonical encoding, and quarantine (never delete, never guess) for
// unknown schema versions or corrupt files.
package recipes
