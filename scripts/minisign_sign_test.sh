#!/usr/bin/env bash
# Self-tests for the SB-SEC02 signing-credential binding check.
#
# The release signer must refuse to sign with a credential that does not
# correspond to the pinned public key. Without this, a substituted or
# misconfigured secret yields a signature no client accepts - and the
# mismatch surfaces only after artifacts are published.
#
# All keys here are generated fresh in a temp dir. No production material.
set -uo pipefail
set +e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

PASS=0; FAIL=0
ok()  { echo "PASS [$1]"; PASS=$((PASS + 1)); }
bad() { echo "FAIL [$1]"; FAIL=$((FAIL + 1)); }

command -v go >/dev/null 2>&1 || { echo "BLOCKED: go toolchain not available" >&2; exit 2; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
TOOL="$TMP/minisign"
go build -o "$TOOL" ./scripts/minisign.go >/dev/null 2>&1 || { bad "build"; exit 1; }

gen() { # gen <name> -> writes <TMP>/<name>.pub and .key
  ( cd "$TMP" && "$TOOL" keygen -p "$1.pub" -s "$1.key" >/dev/null 2>&1 )
}

gen signer
gen other
printf 'payload\n' > "$TMP/msg.txt"

# --- T1: matching credential signs successfully ---
if ( cd "$TMP" && "$TOOL" sign -m msg.txt -s signer.key -p signer.pub -x t1.minisig >/dev/null 2>&1 ) \
   && [ -s "$TMP/t1.minisig" ]; then
  ok "T1 matching credential signs"
else
  bad "T1 matching credential should sign"
fi

# --- T2: mismatched credential is refused (the SEC02 property) ---
OUT="$( cd "$TMP" && "$TOOL" sign -m msg.txt -s other.key -p signer.pub -x t2.minisig 2>&1 )"
RC=$?
if [ $RC -ne 0 ] && grep -qi "does not match" <<<"$OUT"; then
  ok "T2 mismatched credential refused with an explicit reason"
else
  bad "T2 mismatched credential not refused (rc=${RC}, out=${OUT})"
fi

# --- T3: refusal writes no signature file (nothing half-done to publish) ---
if [ ! -f "$TMP/t2.minisig" ]; then
  ok "T3 no signature file produced on refusal"
else
  bad "T3 signature file written despite refusal"
fi

# --- T4: existing signature is not overwritten on refusal ---
printf 'sentinel\n' > "$TMP/t4.minisig"
( cd "$TMP" && "$TOOL" sign -m msg.txt -s other.key -p signer.pub -x t4.minisig >/dev/null 2>&1 )
if [ "$(cat "$TMP/t4.minisig")" = "sentinel" ]; then
  ok "T4 existing signature left untouched on refusal"
else
  bad "T4 refusal overwrote an existing signature"
fi

# --- T5: unreadable/invalid public key file is refused, not silently ignored ---
printf 'not a key\n' > "$TMP/garbage.pub"
OUT="$( cd "$TMP" && "$TOOL" sign -m msg.txt -s signer.key -p garbage.pub -x t5.minisig 2>&1 )"
RC=$?
if [ $RC -ne 0 ] && [ ! -f "$TMP/t5.minisig" ]; then
  ok "T5 invalid public key file refused"
else
  bad "T5 invalid public key file accepted (rc=${RC})"
fi

# --- T6: signature from a matching credential verifies against that pubkey ---
if ( cd "$TMP" && "$TOOL" verify -m msg.txt -p signer.pub -x t1.minisig -q >/dev/null 2>&1 ); then
  ok "T6 matching signature verifies"
else
  bad "T6 matching signature failed to verify"
fi

# --- T7: a signature from one key does not verify under another ---
if ( cd "$TMP" && "$TOOL" verify -m msg.txt -p other.pub -x t1.minisig -q >/dev/null 2>&1 ); then
  bad "T7 signature verified under the wrong key"
else
  ok "T7 signature rejected under the wrong key"
fi

echo
echo "minisign signer self-tests: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
