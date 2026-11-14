#!/bin/bash
# SEC01 guard self-tests (fail-closed assertions, self-scan safe).
set -euo pipefail
GUARD_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_FOR_GUARD=$(cd "$GUARD_DIR/.." && pwd)
GUARD="$GUARD_DIR/guard-signing-material.sh"
RETIRED="${RETIRED_P1}""${RETIRED_P2}"
PIN_B64="RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_clean() {
  if bash "$GUARD" --scan-dir "$1" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL(expected clean): $1"; fi
}
check_reject() {
  if bash "$GUARD" --scan-dir "$1" >/dev/null 2>&1; then FAIL=$((FAIL+1)); echo "FAIL(expected reject): $1"; else PASS=$((PASS+1)); fi
}

# T1: ordinary go file with a random test seed -> clean
mkdir -p "$TMP/t1"
printf 'package t\n\nconst k = "%s"\n' "$(python3 -c 'import os; print(os.urandom(32).hex())')" > "$TMP/t1/a_test.go"
check_clean "$TMP/t1"

# T2: the retired production-derived seed -> reject
mkdir -p "$TMP/t2"
printf 'package t\nconst k = "%s"\n' "$RETIRED" > "$TMP/t2/seed.go"
check_reject "$TMP/t2"

# T3: same seed assembled from split halves (key-bound scan catches the
# derived key even when the source never spells the literal)
mkdir -p "$TMP/t3"
python3 - "$TMP/t3" <<'PYEOF'
import sys
half1 = "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533a"
half2 = "d"
open(sys.argv[1] + "/split.go", "w").write('package t\nconst k = "%s%s"\n' % (half1, half2))
PYEOF
check_reject "$TMP/t3"

# T4: production pin base64 hardwired in a TEST file -> reject (rule 2)
mkdir -p "$TMP/t4"
printf 'package t\nconst pin = "%s"\n' "$PIN_B64" > "$TMP/t4/pin_test.go"
check_reject "$TMP/t4"

# T5: benign content -> clean
mkdir -p "$TMP/t5"
printf 'package t\nconst msg = "hello world"\n' > "$TMP/t5/x.go"
check_clean "$TMP/t5"

# T6: test file referencing the production pin SYMBOL -> reject (rule 2b)
mkdir -p "$TMP/t6"
printf 'package t\nconst p = DefaultMinisignPublicKey\n' > "$TMP/t6/ref_test.go"
check_reject "$TMP/t6"

# T7: retired seed hidden in a NON-go file -> reject (rule 1 is type-agnostic)
mkdir -p "$TMP/t7"
printf 'notes: %s\n' "$RETIRED" > "$TMP/t7/notes.md"
check_reject "$TMP/t7"

# T8 (crypto-path discriminator): the key-bound scan must actually DERIVE
# public keys. A fresh random seed scanned against ITS OWN derived pin must
# be rejected. If the RFC 8032 derivation were broken (never matches), this
# assertion would fail.
mkdir -p "$TMP/t8"
T8SEED=$(python3 -c "import os; print(os.urandom(32).hex())")
T8PIN=$(python3 -c "
import base64, importlib.util, sys
spec = importlib.util.spec_from_file_location('g', '$GUARD_DIR/guard-signing-material.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
pub = g.ed25519_public_key(bytes.fromhex('$T8SEED'))
print(base64.b64encode(b'Ed' + b'12345678' + pub).decode())
")
printf 'package t\nconst k = "%s"\n' "$T8SEED" > "$TMP/t8/derived.go"
if PIN_B64="$T8PIN" python3 "$GUARD_DIR/guard-signing-material.py" --scan-dir "$TMP/t8" | grep -q "derives"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); echo "FAIL(crypto path): key-bound scan did not derive a matching key"
fi

# T9 (trust-root consistency, positive): matching minisign.pub + verify.go
# pin in a tracked-layout copy -> no trust-root violation.
mkdir -p "$TMP/t9/packages/engine/updater"
printf 'untrusted comment: minisign public key\n%s\n' "$PIN_B64" > "$TMP/t9/minisign.pub"
printf 'package updater\n\nconst DefaultMinisignPublicKey = "%s"\n' "$PIN_B64" > "$TMP/t9/packages/engine/updater/verify.go"
CONS=$( (cd "$TMP/t9" && PIN_B64="$PIN_B64" SANCTIONED_PIN_FILES="packages/engine/updater/verify.go" \
  python3 "$GUARD_DIR/guard-signing-material.py" 2>/dev/null) )
if [ -z "$CONS" ] || ! echo "$CONS" | grep -q "trust-root"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL(t9): matching pin reported as violation"; fi

# T10 (trust-root consistency, negative): MISMATCHED pair -> violation.
mkdir -p "$TMP/t10/packages/engine/updater"
printf 'untrusted comment: minisign public key\n%s\n' "$PIN_B64" > "$TMP/t10/minisign.pub"
printf 'package updater\n\nconst DefaultMinisignPublicKey = "%s"\n' "${PIN_B64%?}F" > "$TMP/t10/packages/engine/updater/verify.go"
CONS=$( (cd "$TMP/t10" && PIN_B64="$PIN_B64" SANCTIONED_PIN_FILES="packages/engine/updater/verify.go" \
  python3 "$GUARD_DIR/guard-signing-material.py" 2>/dev/null) )
if echo "$CONS" | grep -q "trust-root mismatch"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL(t10): mismatched trust root not detected"; fi

# --- SEC02 Phase C: legacy update-channel resurrection ----------------
# These run against the REAL worktree (tracked mode), because rule 6 only
# applies to tracked files. Each case stages a file, asserts rejection, and
# removes it again -- no state survives the test.

# The guard's rules 6/7 apply to TRACKED files, so the probe must be staged
# for the rejection to be meaningful. The file is removed and the index entry
# dropped again in all paths (including on failure).
stage_and_check_reject() {
  local name="$1" path="$2" content="$3"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$content" > "$path"
  git add -f "$path" >/dev/null 2>&1
  if bash "$GUARD" >/dev/null 2>&1; then
    FAIL=$((FAIL+1)); echo "FAIL(expected reject): $name"
  else
    PASS=$((PASS+1))
  fi
  git rm -q --cached "$path" >/dev/null 2>&1 || true
  rm -f "$path"
}

stage_and_check_reject   "T11 tracked legacy updates/ manifest"   "updates/stable.json"   '{"schema_version":1,"version":"9.9.9","channel":"stable"}'

stage_and_check_reject   "T12 published channel manifest outside updates/"   "docs/stable.json"   '{"schema_version":1,"version":"9.9.9","channel":"stable"}'

stage_and_check_reject   "T13 retired credential wired into a workflow"   ".github/workflows/__sec02_probe.yml"   'env:
  MINISIGN_SECRET_KEY_LEGACY: ${{ secrets.OLD }}
'

# Cleanup safety: the probe files must not survive any path above.
rm -rf updates docs/stable.json .github/workflows/__sec02_probe.yml

cd "$ROOT_FOR_GUARD" 2>/dev/null || true

# T15: a non-manifest file inside updates/ must still be rejected.
# T11 uses updates/stable.json, which the manifest-name rule also catches, so
# it cannot isolate the directory rule. This probe (an innocuous README inside
# the channel directory) is the discriminator for "tracked updates/ directory".
stage_and_check_reject \
  "T15 any tracked file under updates/" \
  "updates/README.md" \
  'placeholder content, not a manifest'

# T14: an ordinary docs file is still clean (rule 6 must not reject broadly).
mkdir -p "$TMP/t14"
printf 'not a manifest
' > "$TMP/t14/notes.md"
check_clean "$TMP/t14"

echo "guard-signing-material self-tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
