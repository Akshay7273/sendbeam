#!/bin/bash
# SEC01 — production signing-key material guard (fail-closed, CI-enforced).
#
# Background: the retired test fixture seed removed by SEC01 derived the
# exact pinned production update-signing trust anchor (public key bytes
# verified byte-identical). This guard prevents recurrence:
#
#   1. The retired seed literal must never reappear in ANY tracked file.
#   2. The production pinned public key (base64 form) may appear ONLY in the
#      sanctioned engine verification file — tests and tooling must bind to
#      independent disposable keys (sec01_testkeys_test.go), never to the
#      production pin.
#   3. Any 64-hex literal in tracked Go files that DERIVES the production
#      public key (Ed25519) is refused — catching deterministic re-derivation
#      schemes, not just the one retired literal.
#
# No secret material exists in this script: the pinned value is a public key.
# Fingerprint outputs are SHA-256 digests, never raw keys.
#
# Usage: guard-signing-material.sh [--scan-dir DIR]
#   --scan-dir DIR : scan every file under DIR instead of git-tracked files
#                    (used by the self-test suite; cannot be combined with
#                    a real worktree scan unless DIR is inside one).
set -euo pipefail

PIN_B64="RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE"
# Retired seed literal intentionally NOT stored here (self-scan safe);
# the python core assembles it from split parts.
SANCTIONED_PIN_FILES="packages/engine/updater/verify.go"

command -v python3 >/dev/null 2>&1 || { echo "[-] SEC01 GUARD: python3 is required" >&2; exit 1; }

MODE_ARGS=()
if [ "${1:-}" = "--scan-dir" ]; then
  [ -n "${2:-}" ] || { echo "[-] SEC01 GUARD: --scan-dir requires a directory" >&2; exit 1; }
  MODE_ARGS=(--scan-dir "$2")
fi

VIOLATIONS=$(PIN_B64="$PIN_B64" \
  SANCTIONED_PIN_FILES="$SANCTIONED_PIN_FILES" python3 scripts/guard-signing-material.py "${MODE_ARGS[@]}")

if [ -n "$VIOLATIONS" ]; then
  echo "[-] SEC01 GUARD: production-bound signing material detected:" >&2
  echo "$VIOLATIONS" >&2
  exit 1
fi
echo "[+] SEC01 GUARD: no production-bound signing material in tracked files."
