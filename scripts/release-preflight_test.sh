#!/usr/bin/env bash
# release-preflight_test.sh — self-tests for release-preflight.sh.
#
# Verifies the preflight accepts valid ready metadata and rejects the failure
# modes it claims to catch. Runs in a temp copy so a failing assertion cannot
# be masked by, or corrupt, the working tree.
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $*"; }

# assert_exit <expected> <description> <cmd...>
assert_exit() {
  local want="$1" desc="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$desc (exit $rc)"; else bad "$desc (expected exit $want, got $rc)"; echo "$out" | sed 's/^/        /' | head -5; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "=== release-preflight self-tests ==="

# --- T1: a well-formed unpublished version is accepted ---------------------
assert_exit 0 "T1 accepts an unpublished, well-formed version" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh" 2.3.0

# --- T2: v-prefixed input is accepted (normalized) -------------------------
assert_exit 0 "T2 accepts a v-prefixed version" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh" v2.3.0

# --- T3: malformed version is rejected as a usage error --------------------
assert_exit 2 "T3 rejects a non-SemVer argument" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh" 2.3

assert_exit 2 "T4 rejects an empty argument" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh"

# --- T5: an already-tagged version must not pass preflight -----------------
assert_exit 1 "T5 rejects an already-published tag as new work" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh" 2.2.0

# --- T6: a version older than the newest tag is rejected -------------------
assert_exit 1 "T6 rejects a version older than the newest published tag" \
  bash "${ROOT_DIR}/scripts/release-preflight.sh" 1.5.0

# --- T7/T8: sandbox copies with one thing broken ---------------------------
# The preflight reads git tags, so each sandbox needs real git history;
# otherwise it exits with a git error instead of the assertion under test and
# the test would "pass" for the wrong reason. The sandbox is a clone of the
# real repo (no network, local objects only) with one mutation applied.
make_sandbox() {
  local name="$1"
  local dir="$TMP/$name"
  git clone -q --no-hardlinks --shared "${ROOT_DIR}" "$dir" 2>/dev/null || return 1
  git -C "$dir" checkout -q HEAD 2>/dev/null || return 1
  # The clone only has committed content; carry the working-tree scripts so
  # the sandbox exercises the version of the preflight under test.
  cp "${ROOT_DIR}/scripts/release-preflight.sh" "$dir/scripts/" 2>/dev/null || return 1
  cp "${ROOT_DIR}/scripts/docs-consistency.sh" "$dir/scripts/" 2>/dev/null || return 1
  echo "$dir"
}

# --- T7: version constants that claim a release version are caught ---------
T7="$(make_sandbox t7)" || bad "T7 sandbox setup failed"
if [ -n "${T7:-}" ]; then
  sed -i 's/Version = "dev"/Version = "2.3.0"/' "$T7/apps/cli/cmd/sendbeam/version.go"
  assert_exit 1 "T7 catches a version constant that claims a release version" \
    bash -c "cd '$T7' && bash scripts/release-preflight.sh 2.3.0"
fi

# --- T8: a weakened release workflow is caught -----------------------------
T8="$(make_sandbox t8)" || bad "T8 sandbox setup failed"
if [ -n "${T8:-}" ]; then
  sed -i 's/Assert source binding/Assert nothing/' "$T8/.github/workflows/release.yml"
  assert_exit 1 "T8 catches removal of the source-binding assertion" \
    bash -c "cd '$T8' && bash scripts/release-preflight.sh 2.3.0"
fi

# --- T10: an untagged/shallow clone must fail closed, not report ready -----
# With no visible tags the ordering checks would trivially pass; the preflight
# must refuse to give a verdict instead of silently approving anything.
T10="$TMP/t10"
mkdir -p "$T10/scripts"
git -C "$T10" init -q 2>/dev/null
git -C "$T10" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init 2>/dev/null
cp "${ROOT_DIR}/scripts/release-preflight.sh" "$T10/scripts/"
cmp -s "${ROOT_DIR}/scripts/docs-consistency.sh" "$T10/scripts/docs-consistency.sh" 2>/dev/null || cp "${ROOT_DIR}/scripts/docs-consistency.sh" "$T10/scripts/"
mkdir -p "$T10/apps"
cp -r "${ROOT_DIR}/apps/cli" "${ROOT_DIR}/apps/desktop" "$T10/apps/" 2>/dev/null || true
mkdir -p "$T10/.github/workflows"
cp "${ROOT_DIR}/.github/workflows/release.yml" "$T10/.github/workflows/" 2>/dev/null || true
assert_exit 2 "T10 fails closed when no tags are visible (shallow clone)" \
  bash -c "cd '$T10' && bash scripts/release-preflight.sh 2.3.0"

# --- T9: preflight must never create a tag or release ---------------------
BEFORE="$(git -C "$ROOT_DIR" tag --list | wc -l)"
bash "${ROOT_DIR}/scripts/release-preflight.sh" 2.3.0 >/dev/null 2>&1 || true
AFTER="$(git -C "$ROOT_DIR" tag --list | wc -l)"
if [ "$BEFORE" = "$AFTER" ]; then ok "T9 creates no tags"; else bad "T9 created a tag ($BEFORE -> $AFTER)"; fi

echo ""
echo "=== RESULTS: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ] || exit 1
