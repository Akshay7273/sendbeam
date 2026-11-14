#!/usr/bin/env bash
# acceptance-record_test.sh — deterministic self-tests for the SB-R10
# evidence recorder (scripts/acceptance-record.sh).
#
# Covers: valid PASS/FAIL/BLOCKED/NOT RUN/NOT APPLICABLE rows; the
# anti-fabrication gate (incomplete PASS, digest-less transfer PASS, bad
# sha, bad timestamp, duplicate id, unknown fields, secret-shaped payload);
# report generation; and idempotent re-validation of a clean file.
#
# Exit: 0 = all cases passed; 1 = at least one failure.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="${ROOT_DIR}/scripts/acceptance-record.sh"

failures=0
cases=0

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

TS="2026-11-14T12:00:00Z"
SHA="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SHA2="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

check() { # check <label> <expect-substring> <output>
  cases=$((cases + 1))
  if printf '%s' "$3" | grep -q "$2"; then
    printf 'ok %2d - %s\n' "$cases" "$1"
  else
    failures=$((failures + 1))
    printf 'not ok %2d - %s\n' "$cases" "$1"
    printf '      expected %s in: %s\n' "$2" "$3" | head -3 >&2
  fi
}

E="$tmp/ev.jsonl"

# --- 1: valid PASS artifact row -------------------------------------------
out="$(bash "$R" record "$E" A-inspect PASS os=linux arch=amd64 artifact-sha="$SHA" exe-version=0.0.0~dev source-sha="$SHA2" operator=qa timestamp="$TS" evidence="run-1" mode=none 2>&1)"
check "valid PASS row recorded+validated" "OK: 1 row(s) valid" "$out"

# --- 2: valid FAIL row -----------------------------------------------------
out="$(bash "$R" record "$E" C-launch FAIL os=windows arch=amd64 source-sha="$SHA" operator=qa timestamp="$TS" evidence="shot-2" reason="app did not launch" 2>&1)"
check "valid FAIL row" "OK: 2 row(s) valid" "$out"

# --- 3: valid BLOCKED row --------------------------------------------------
out="$(bash "$R" record "$E" C-install-mac BLOCKED reason="no macOS host in environment" 2>&1)"
check "valid BLOCKED row" "OK: 3 row(s) valid" "$out"

# --- 4: valid NOT RUN row --------------------------------------------------
out="$(bash "$R" record "$E" D-relay "NOT RUN" reason="no second device" 2>&1)"
check "valid NOT RUN row" "OK: 4 row(s) valid" "$out"

# --- 5: valid NOT APPLICABLE row ------------------------------------------
out="$(bash "$R" record "$E" D-mobile "NOT APPLICABLE" reason="native mobile deferred by owner decision" 2>&1)"
check "valid NOT APPLICABLE row" "OK: 5 row(s) valid" "$out"

# --- 6: fabricated PASS (no provenance) must be rejected -------------------
out="$(bash "$R" record "$E" C-install-win PASS os=windows arch=amd64 2>&1)"
check "fabricated PASS rejected" "FABRICATED PASS rejected" "$out"

# --- 7: PASS transfer row without digest rejected --------------------------
rm -f "$tmp/e2.jsonl"
out="$(bash "$R" record "$tmp/e2.jsonl" D-transfer PASS os=linux arch=amd64 artifact-sha="$SHA" exe-version=x source-sha="$SHA2" operator=qa timestamp="$TS" evidence=photo 2>&1)"
check "PASS transfer row without digest rejected" "needs a sha256 digest" "$out"

# --- 8: bad sha rejected ----------------------------------------------------
rm -f "$tmp/e3.jsonl"
out="$(bash "$R" record "$tmp/e3.jsonl" B-row PASS os=linux arch=amd64 artifact-sha=FAKE exe-version=x source-sha="$SHA" operator=qa timestamp="$TS" evidence=e8 mode=none 2>&1)"
check "non-hex artifact sha rejected" "must be 64 lowercase hex" "$out"

# --- 9: duplicate id rejected ----------------------------------------------
rm -f "$tmp/e4.jsonl"
bash "$R" record "$tmp/e4.jsonl" A-row PASS os=linux arch=amd64 artifact-sha="$SHA" exe-version=x source-sha="$SHA2" operator=qa timestamp="$TS" evidence=a mode=none >/dev/null 2>&1
out="$(bash "$R" record "$tmp/e4.jsonl" A-row PASS os=linux arch=amd64 artifact-sha="$SHA" exe-version=x source-sha="$SHA2" operator=qa timestamp="$TS" evidence=b mode=none 2>&1)"
check "duplicate id rejected" "duplicate id" "$out"

# --- 10: bad timestamp rejected ---------------------------------------------
rm -f "$tmp/e5.jsonl"
out="$(bash "$R" record "$tmp/e5.jsonl" T-row PASS os=linux arch=amd64 artifact-sha="$SHA" exe-version=x source-sha="$SHA2" operator=qa timestamp=yesterday evidence=t mode=none 2>&1)"
check "non-RFC3339 timestamp rejected" "RFC3339" "$out"

# --- 11: unknown fields (secret-shaped payload) rejected --------------------
rm -f "$tmp/e6.jsonl"
out="$(bash "$R" record "$tmp/e6.jsonl" S-row PASS token=supersecret password=hunter2 os=linux arch=amd64 artifact-sha="$SHA" exe-version=x source-sha="$SHA2" operator=qa timestamp="$TS" evidence=s mode=none 2>&1)"
check "unknown/secret fields rejected" "unknown field" "$out"

# --- 12: clean file revalidates idempotently --------------------------------
out="$(bash "$R" validate "$E" 2>&1)"
check "clean file revalidates" "OK: 5 row(s) valid" "$out"

# --- 13: report renders all rows with categories ----------------------------
out="$(bash "$R" report "$E" 2>&1)"
check "report shows PASS count" "| PASS | 1 |" "$out"
check "report shows BLOCKED row id" "## C-install-mac — BLOCKED" "$out"
check "report shows NOT APPLICABLE row" "## D-mobile — NOT APPLICABLE" "$out"

# --- 14: report of a file WITH a rejected row still refuses -----------------
printf '{"id":"B-row","result":"PASS","os":"linux"}\n' >> "$E"
out="$(bash "$R" validate "$E" 2>&1)"
check "file with fabricated row fails validation" "FABRICATED PASS rejected" "$out"

printf '\n%d case(s), %d failure(s)\n' "$cases" "$failures"
[ "$failures" -eq 0 ] || exit 1
exit 0
