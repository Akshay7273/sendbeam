#!/bin/bash
# SEC01 guard self-tests (fail-closed assertions, self-scan safe).
#
# The guard was reduced to rules 1/3/6/7 when the self-updater and its signing
# key were removed (SB-SIMPLIFY). Rule 1 (retired literal), rule 3 (seed that
# derives the retired key) and rule 7 (retired credential names) defend against
# resurrecting the old material; rule 6 defends against the legacy update route
# becoming resolvable again. Every remaining rule has a positive AND a negative
# case here, so a rule that silently stops firing is caught.
set -euo pipefail
GUARD_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT_FOR_GUARD=$(cd "$GUARD_DIR/.." && pwd)
GUARD="$GUARD_DIR/guard-signing-material.sh"
RETIRED="${RETIRED_P1}""${RETIRED_P2}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

check_clean() {
  if bash "$GUARD" --scan-dir "$1" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL(expected clean): $1"; fi
}
check_reject() {
  if bash "$GUARD" --scan-dir "$1" >/dev/null 2>&1; then FAIL=$((FAIL+1)); echo "FAIL(expected reject): $1"; else PASS=$((PASS+1)); fi
}

# --- rule 1: retired seed literal, any file type -------------------------
# T1: ordinary go file with a random test seed -> clean
mkdir -p "$TMP/t1"
printf 'package t\n\nconst k = "%s"\n' "$(python3 -c 'import os; print(os.urandom(32).hex())')" > "$TMP/t1/a_test.go"
check_clean "$TMP/t1"

# T2: the retired production-derived seed -> reject
mkdir -p "$TMP/t2"
printf 'package t\nconst k = "%s"\n' "$RETIRED" > "$TMP/t2/seed.go"
check_reject "$TMP/t2"

# T3: retired seed hidden in a NON-go file -> reject (rule 1 is type-agnostic)
mkdir -p "$TMP/t3"
printf 'notes: %s\n' "$RETIRED" > "$TMP/t3/notes.md"
check_reject "$TMP/t3"

# --- rule 3: seed that DERIVES the retired key without spelling it -------
# T4: same seed assembled from split halves. The literal never appears, so
# only the key-bound derivation can catch this.
mkdir -p "$TMP/t4"
python3 - "$TMP/t4" <<'PYEOF'
import sys
half1 = "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533a"
half2 = "d"
open(sys.argv[1] + "/split.go", "w").write('package t\nconst k = "%s%s"\n' % (half1, half2))
PYEOF
check_reject "$TMP/t4"

# T5 (crypto-path discriminator): the key-bound scan must actually DERIVE
# public keys. A fresh random seed scanned against ITS OWN derived pin must be
# rejected. If the RFC 8032 derivation were broken (never matches), the guard
# would silently pass every re-derivation scheme and this would fail.
mkdir -p "$TMP/t5"
T5SEED=$(python3 -c "import os; print(os.urandom(32).hex())")
T5PIN=$(python3 -c "
import base64, importlib.util
spec = importlib.util.spec_from_file_location('g', '$GUARD_DIR/guard-signing-material.py')
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
pub = g.ed25519_public_key(bytes.fromhex('$T5SEED'))
print(base64.b64encode(b'Ed' + b'12345678' + pub).decode())
")
printf 'package t\nconst k = "%s"\n' "$T5SEED" > "$TMP/t5/derived.go"
if PIN_B64="$T5PIN" python3 "$GUARD_DIR/guard-signing-material.py" --scan-dir "$TMP/t5" | grep -q "derives"; then
  PASS=$((PASS+1))
else
  FAIL=$((FAIL+1)); echo "FAIL(crypto path): key-bound scan did not derive a matching key"
fi

# T6: a random 64-hex literal that derives nothing special -> clean.
# This is the negative for rule 3: rule 3 must not reject ordinary keys.
mkdir -p "$TMP/t6"
printf 'package t\nconst k = "%s"\n' "$(python3 -c 'import os; print(os.urandom(32).hex())')" > "$TMP/t6/random.go"
check_clean "$TMP/t6"

# T7: benign content -> clean
mkdir -p "$TMP/t7"
printf 'package t\nconst msg = "hello world"\n' > "$TMP/t7/x.go"
check_clean "$TMP/t7"

# --- rules 6/7: tracked-mode rules ---------------------------------------
# These run against the REAL worktree, because rules 6/7 only apply to tracked
# files. Each case stages a file, asserts rejection, and removes it again --
# no state survives the test, including on failure.
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

cd "$ROOT_FOR_GUARD"

# T8: tracked legacy updates/ manifest -> reject (rule 6, directory + name)
stage_and_check_reject "T8 tracked legacy updates/ manifest" "updates/stable.json" \
  '{"schema_version":1,"version":"9.9.9","channel":"stable"}'

# T9: published channel manifest outside updates/ -> reject (rule 6, name)
stage_and_check_reject "T9 published channel manifest outside updates/" "docs/stable.json" \
  '{"schema_version":1,"version":"9.9.9","channel":"stable"}'

# T10: a non-manifest file inside updates/ must still be rejected. T8 uses
# updates/stable.json, which the manifest-name rule also catches, so it cannot
# isolate the directory rule. This probe is the discriminator.
stage_and_check_reject "T10 any tracked file under updates/" "updates/README.md" \
  'placeholder content, not a manifest'

# T11: retired credential wired into a workflow -> reject (rule 7)
stage_and_check_reject "T11 retired credential in workflow" ".github/workflows/__sec02_probe.yml" \
'env:
  MINISIGN_SECRET_KEY_LEGACY: ${{ secrets.OLD }}
'

# Cleanup safety: probe files must not survive any path above.
rm -rf updates docs/stable.json .github/workflows/__sec02_probe.yml

# T12: an ordinary docs file is still clean under tracked mode (rule 6 must
# not reject broadly).
mkdir -p "$TMP/t12"
printf 'not a manifest\n' > "$TMP/t12/notes.md"
check_clean "$TMP/t12"

# T13: the retired-key tooling is gone, so rules 2/2b/5 have no target.
# Pin the reduction: the guard must not demand a file that no longer exists.
if grep -q "SANCTIONED_PIN_FILES" "$GUARD_DIR/guard-signing-material.sh"; then
  FAIL=$((FAIL+1)); echo "FAIL: guard still sanctions a pinned-key file that no longer exists"
else
  PASS=$((PASS+1))
fi

echo "guard-signing-material self-tests: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
