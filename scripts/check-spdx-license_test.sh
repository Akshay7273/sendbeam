#!/usr/bin/env bash
# check-spdx-license_test.sh — mutation self-test for check-spdx-license.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/check-spdx-license.py

TMP="apps/web/src/.spdx-license-mutation.$$.py"
trap 'git restore --staged -- "$TMP" 2>/dev/null || true; git restore -- "$TMP" 2>/dev/null || rm -f "$TMP"' EXIT

# Build the conflicting declaration from fragments so this script itself
# never contains a literal SPDX license declaration (the checker scans it).
spdx='SPDX-License-'
printf '%s%s %s\n' "// ${spdx}" 'Identifier: AGPL-3.0-only' > "$TMP"
git add -f "$TMP"

if python3 scripts/check-spdx-license.py >/dev/null 2>&1; then
  echo 'SPDX check did not reject a conflicting declaration' >&2
  exit 1
fi
git restore --staged -- "$TMP"
trap - EXIT
echo 'SPDX consistency self-test passed: conflicting declaration rejected'
