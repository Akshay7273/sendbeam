#!/bin/bash
# SEC01 — retired signing-material guard (fail-closed, CI-enforced).
#
# Background: SendBeam once shipped an automatic self-updater that decided "is
# this binary authentic?" unattended, which required a long-lived production
# signing key. A retired test fixture seed derived that key. The updater and
# its key were removed at the root (SB-SIMPLIFY); manual GitHub Releases
# downloads with build-provenance attestations replaced them.
#
# Removing the key does not remove the risk. The remaining risk is
# resurrection: someone reintroducing the retired material, or a legacy update
# route becoming resolvable again so that forged manifests signed with the
# retired key could reach old clients. This guard prevents that:
#
#   1. The retired seed literal must never reappear in ANY tracked file.
#   3. Any 64-hex literal in tracked Go files that DERIVES the retired public
#      key (Ed25519) is refused — catching deterministic re-derivation
#      schemes, not just the one retired literal.
#   6. No tracked legacy update-channel artefacts: no updates/ directory and no
#      published channel manifests, so enabling GitHub Pages cannot resurrect
#      the retired-key route.
#   7. Retired signing-credential names must not be wired into any workflow.
#
# No secret material exists in this script: the retired value is a public key.
# Fingerprint outputs are SHA-256 digests, never raw keys.
#
# Usage: guard-signing-material.sh [--scan-dir DIR]
#   --scan-dir DIR : scan every file under DIR instead of git-tracked files
#                    (used by the self-test suite; rules 6/7 need tracked mode).
set -euo pipefail

# The retired public key. Kept because rule 3 needs a target to derive against:
# it is the only way to catch a seed that reconstructs this key without ever
# spelling the retired literal. This is a public value, never a secret.
RETIRED_PIN_B64="RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE"

command -v python3 >/dev/null 2>&1 || { echo "[-] SEC01 GUARD: python3 is required" >&2; exit 1; }

MODE_ARGS=()
if [ "${1:-}" = "--scan-dir" ]; then
  [ -n "${2:-}" ] || { echo "[-] SEC01 GUARD: --scan-dir requires a directory" >&2; exit 1; }
  MODE_ARGS=(--scan-dir "$2")
fi

VIOLATIONS=$(PIN_B64="$RETIRED_PIN_B64" \
  python3 scripts/guard-signing-material.py "${MODE_ARGS[@]}")

if [ -n "$VIOLATIONS" ]; then
  echo "[-] SEC01 GUARD: retired or resurrection-capable signing material detected:" >&2
  echo "$VIOLATIONS" >&2
  exit 1
fi
echo "[+] SEC01 GUARD: no retired signing material or legacy update route in tracked files."
