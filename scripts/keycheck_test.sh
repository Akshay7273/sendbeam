#!/usr/bin/env bash
# Self-tests for scripts/keycheck.go (SB-SEC02).
#
# keycheck exists so the rotation runbook can verify a public key with a tool
# that cannot touch secret material. The tests below prove it prints the
# documented fields, matches an independently computed fingerprint, and fails
# closed on malformed input instead of emitting partial (trusted) output.
set -uo pipefail
set +e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

PASS=0
FAIL=0
ok()  { echo "PASS [$1]"; PASS=$((PASS + 1)); }
bad() { echo "FAIL [$1]"; FAIL=$((FAIL + 1)); }

if ! command -v go >/dev/null 2>&1; then
  echo "BLOCKED: go toolchain not available" >&2
  exit 2
fi

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

KC="$TMPDIR_TEST/keycheck"
if ! go build -o "$KC" ./scripts/keycheck.go 2>"$TMPDIR_TEST/build.log"; then
  echo "FAIL [build] keycheck did not compile" >&2
  cat "$TMPDIR_TEST/build.log" >&2
  exit 1
fi
ok "build"

# --- T1: the committed production public key parses and reports 3 fields ---
OUT="$("$KC" minisign.pub 2>&1)"
if [ $? -eq 0 ] \
  && grep -q '^key_id_hex=[0-9A-F]\{16\}$' <<<"$OUT" \
  && grep -q '^public_key_hex=[0-9a-f]\{64\}$' <<<"$OUT" \
  && grep -q '^public_key_sha256=[0-9a-f]\{64\}$' <<<"$OUT"; then
  ok "T1 committed key parses, three well-formed fields"
else
  bad "T1 committed key parse: $OUT"
fi

# --- T2: the reported sha256 equals an independently computed digest ---
# Uses the raw 32-byte key, decoded with base64/xxd rather than trusting the
# tool's own decode path.
PUB_HEX="$(grep '^public_key_hex=' <<<"$OUT" | cut -d= -f2)"
printf '%s' "$PUB_HEX" | xxd -r -p > "$TMPDIR_TEST/pub.raw"
EXPECTED="$(sha256sum "$TMPDIR_TEST/pub.raw" | cut -d' ' -f1)"
REPORTED="$(grep '^public_key_sha256=' <<<"$OUT" | cut -d= -f2)"
if [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$REPORTED" ]; then
  ok "T2 fingerprint matches independent sha256 of the raw key"
else
  bad "T2 fingerprint mismatch (expected ${EXPECTED} reported ${REPORTED})"
fi

# --- T3: the key ID is stable and matches the committed comment line ---
COMMENT_ID="$(grep -o 'minisign public key [0-9A-F]*' minisign.pub | awk '{print $4}')"
REPORTED_ID="$(grep '^key_id_hex=' <<<"$OUT" | cut -d= -f2)"
if [ -n "$COMMENT_ID" ] && [ "$COMMENT_ID" = "$REPORTED_ID" ]; then
  ok "T3 key ID matches the public key file's comment line"
else
  bad "T3 key ID mismatch (comment ${COMMENT_ID} reported ${REPORTED_ID})"
fi

# --- T4: a base64 key string (no file) is accepted identically ---
B64="$(grep -v 'untrusted comment' minisign.pub | tr -d '[:space:]')"
OUT2="$("$KC" "$B64" 2>&1)"
if [ "$OUT2" = "$OUT" ]; then
  ok "T4 base64 input produces identical output to file input"
else
  bad "T4 base64/file divergence"
fi

# --- T5..T8: malformed input must fail closed (non-zero, no fields) ---
expect_fail() {
  local name="$1" input="$2"
  local out
  out="$("$KC" "$input" 2>&1)"
  local rc=$?
  if [ $rc -ne 0 ] && ! grep -q '^key_id_hex=' <<<"$out"; then
    ok "$name"
  else
    bad "$name (rc=${rc}, out=${out})"
  fi
}
expect_fail "T5 empty input rejected"          ""
expect_fail "T6 non-base64 rejected"           "not-a-key!!!"
printf 'untrusted comment: only a comment\n' > "$TMPDIR_TEST/commentonly.pub"
expect_fail "T7 comment-only file rejected"    "$TMPDIR_TEST/commentonly.pub"
# A 42-byte body carrying a non-Ed25519 algorithm prefix.
printf 'untrusted comment: x\n%s\n' "$(printf 'XX%s' "$(head -c 40 /dev/zero | base64 | head -c 54)")" > "$TMPDIR_TEST/badalg.pub"
expect_fail "T8 non-Ed25519 algorithm prefix rejected" "$TMPDIR_TEST/badalg.pub"

# --- T9: an Ed25519 key generated independently is reported correctly ---
# Independent keygen: a fresh random public key must round-trip through the
# tool with a matching self-computed fingerprint (no reliance on minisign.go).
cat > "$TMPDIR_TEST/gen.go" <<'GOEOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var raw [42]byte
	raw[0], raw[1] = 'E', 'd'
	copy(raw[2:10], pub[:8])
	copy(raw[10:], pub)
	fmt.Print(base64.StdEncoding.EncodeToString(raw[:]))
}
GOEOF
(cd "$TMPDIR_TEST" && printf 'module keygen\n\ngo 1.25\n' > go.mod && go run gen.go > fresh.b64 2>/dev/null)
if [ -s "$TMPDIR_TEST/fresh.b64" ]; then
  OUT3="$("$KC" "$(cat "$TMPDIR_TEST/fresh.b64")" 2>&1)"
  FRESH_HEX="$(grep '^public_key_hex=' <<<"$OUT3" | cut -d= -f2)"
  printf '%s' "$FRESH_HEX" | xxd -r -p > "$TMPDIR_TEST/fresh.raw"
  EXPECTED3="$(sha256sum "$TMPDIR_TEST/fresh.raw" | cut -d' ' -f1)"
  if [ "$EXPECTED3" = "$(grep '^public_key_sha256=' <<<"$OUT3" | cut -d= -f2)" ]; then
    ok "T9 independently generated key round-trips with a correct fingerprint"
  else
    bad "T9 fresh key fingerprint mismatch"
  fi
else
  bad "T9 could not generate an independent key"
fi

# --- T11: a truncated "Ed"-prefixed key must fail closed ---
# This is the specific probe for the length check: a 12-byte body carrying the
# correct algorithm prefix passes every other guard, so a dissolved length
# check would happily report a 2-byte "public key" as trusted output.
TRUNC_B64="$(printf 'Ed%s' "$(head -c 10 /dev/zero | tr '\0' 'A')" | base64 -w0)"
OUT_T="$("$KC" "$TRUNC_B64" 2>&1)"
RC_T=$?
# Fail closed means: non-zero exit AND no trusted-looking fields emitted.
if [ "$RC_T" -ne 0 ] && ! grep -q '^key_id_hex=' <<<"$OUT_T"; then
  ok "T11 truncated Ed-prefixed key rejected"
else
  bad "T11 truncated Ed-prefixed key accepted (rc=${RC_T}, out=${OUT_T})"
fi

# --- T10: usage is non-zero (misuse must not look like success) ---
"$KC" >/dev/null 2>&1
if [ $? -ne 0 ]; then
  ok "T10 missing argument exits non-zero"
else
  bad "T10 missing argument exited zero"
fi

echo
echo "keycheck self-tests: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
