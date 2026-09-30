#!/usr/bin/env bash
# ==============================================================================
# SendBeam Release Verification Test Suite
# Tests scripts/verify-release.sh: happy paths, adversarial tamper vectors, and
# the fail-closed policy (missing signatures/tools, zero payloads, reduced modes).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERIFY_SCRIPT="${SCRIPT_DIR}/verify-release.sh"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

PASS=0
FAIL=0

ok()   { echo "PASS [$1]"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL [$1]"; FAIL=$((FAIL + 1)); }

echo "=== Running Release Verification Test Suite ==="

# 1. Generate test keypair (synthetic fixture — never a real signing key)
TEST_PUBKEY="${TMPDIR}/test-minisign.pub"
TEST_SECKEY="${TMPDIR}/test-minisign.key"
go run "${SCRIPT_DIR}/minisign.go" keygen -p "${TEST_PUBKEY}" -s "${TEST_SECKEY}" >/dev/null

TEST_SEED="$(grep -v '^untrusted' "${TEST_SECKEY}" | head -n 1)"

# 2. Setup mock release assets
WORKDIR="${TMPDIR}/release-test"
mkdir -p "${WORKDIR}"

echo "binary linux amd64 payload content v1.6.0" > "${WORKDIR}/sendbeam-cli-linux-amd64.tar.gz"
echo "binary darwin arm64 payload content v1.6.0" > "${WORKDIR}/sendbeam-cli-darwin-arm64.tar.gz"
echo "desktop deb payload content v1.6.0" > "${WORKDIR}/sendbeam-desktop_1.6.0_amd64.deb"

(
  cd "${WORKDIR}"
  sha256sum * > SHA256SUMS.txt
  MINISIGN_SECRET_KEY="${TEST_SEED}" go run "${SCRIPT_DIR}/minisign.go" sign -m SHA256SUMS.txt -p "${TEST_PUBKEY}" -x SHA256SUMS.txt.minisig >/dev/null
)

# Test 1: Happy path — checksum-only mode (no bundle in fixture; the bundle-
# required default mode is Test 12).
echo "--- Test 1: Valid artifacts, authenticated manifest, partial payloads (checksum-only) ---"
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null
ok "Test 1: checksum-only happy path"

# Test 2: Tampered file payload
echo "--- Test 2: Tampered file payload ---"
CORRUPT_DIR="${TMPDIR}/corrupt-file"
cp -r "${WORKDIR}" "${CORRUPT_DIR}"
echo "CORRUPTED BYTE" >> "${CORRUPT_DIR}/sendbeam-cli-linux-amd64.tar.gz"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_DIR}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 2: Expected failure on tampered file payload"
else
  ok "Test 2: Correctly rejected tampered payload"
fi

# Test 3: Tampered SHA256SUMS.txt
echo "--- Test 3: Tampered SHA256SUMS.txt ---"
CORRUPT_SUMS="${TMPDIR}/corrupt-sums"
cp -r "${WORKDIR}" "${CORRUPT_SUMS}"
echo "0000000000000000000000000000000000000000000000000000000000000000  fake-file.tar.gz" >> "${CORRUPT_SUMS}/SHA256SUMS.txt"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_SUMS}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 3: Expected failure on tampered SHA256SUMS.txt"
else
  ok "Test 3: Correctly rejected tampered checksums manifest"
fi

# Test 4: Tampered signature file
echo "--- Test 4: Tampered signature file ---"
CORRUPT_SIG="${TMPDIR}/corrupt-sig"
cp -r "${WORKDIR}" "${CORRUPT_SIG}"
sed -i 's/a/b/g' "${CORRUPT_SIG}/SHA256SUMS.txt.minisig"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_SIG}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 4: Expected failure on tampered signature file"
else
  ok "Test 4: Correctly rejected tampered signature"
fi

# Test 5: Wrong public key
echo "--- Test 5: Wrong public key ---"
WRONG_PUBKEY="${TMPDIR}/wrong-minisign.pub"
WRONG_SECKEY="${TMPDIR}/wrong-minisign.key"
go run "${SCRIPT_DIR}/minisign.go" keygen -p "${WRONG_PUBKEY}" -s "${WRONG_SECKEY}" >/dev/null

if "${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${WRONG_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 5: Expected failure on wrong public key"
else
  ok "Test 5: Correctly rejected mismatched public key"
fi

# Test 6: Missing manifest
echo "--- Test 6: Missing SHA256SUMS.txt ---"
EMPTY_DIR="${TMPDIR}/empty"
mkdir -p "${EMPTY_DIR}"

if "${VERIFY_SCRIPT}" --dir "${EMPTY_DIR}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 6: Expected failure on missing SHA256SUMS.txt"
else
  ok "Test 6: Correctly rejected missing manifest"
fi

# Test 7: Missing file in strict mode
echo "--- Test 7: Missing file in strict mode ---"
MISSING_FILE_DIR="${TMPDIR}/missing-file"
cp -r "${WORKDIR}" "${MISSING_FILE_DIR}"
rm "${MISSING_FILE_DIR}/sendbeam-desktop_1.6.0_amd64.deb"

if "${VERIFY_SCRIPT}" --dir "${MISSING_FILE_DIR}" --pubkey "${TEST_PUBKEY}" --strict --checksum-only >/dev/null 2>&1; then
  bad "Test 7: Expected failure on missing file with --strict"
else
  ok "Test 7: Strict mode correctly rejected missing file"
fi

# Test 8: Partial download in checksum-only mode (completeness not asserted)
echo "--- Test 8: Partial download in checksum-only mode ---"
"${VERIFY_SCRIPT}" --dir "${MISSING_FILE_DIR}" --pubkey "${TEST_PUBKEY}" --checksum-only > "${TMPDIR}/t8.out" 2>&1 || true
if grep -q "CHECKSUM-ONLY VERIFICATION PASSED" "${TMPDIR}/t8.out"; then
  ok "Test 8: checksum-only mode verified present files with truthful label"
else
  bad "Test 8: checksum-only mode should verify present files with its own label"
fi

# Test 9 (F01 regression): missing Minisign signature — must fail in EVERY mode
echo "--- Test 9: Missing Minisign signature fails closed ---"
NO_SIG_DIR="${TMPDIR}/no-sig"
cp -r "${WORKDIR}" "${NO_SIG_DIR}"
rm "${NO_SIG_DIR}/SHA256SUMS.txt.minisig"

for MODE in "--checksum-only" "--strict --checksum-only"; do
  if "${VERIFY_SCRIPT}" --dir "${NO_SIG_DIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign ${MODE} >/dev/null 2>&1; then
    bad "Test 9: missing minisig must fail (mode: ${MODE})"
    FAIL_ABORT=1
  fi
done
FAIL_ABORT="${FAIL_ABORT:-0}"
"${VERIFY_SCRIPT}" --dir "${NO_SIG_DIR}" --pubkey "${TEST_PUBKEY}" --checksum-only > "${TMPDIR}/t9.out" 2>&1 || true
if grep -q "ALL RELEASE ASSET VERIFICATIONS PASSED" "${TMPDIR}/t9.out"; then
  bad "Test 9b: official banner must never print after a skipped required check"
else
  ok "Test 9: missing minisign signature fails closed in every mode; no official banner"
fi
unset FAIL_ABORT

# Test 10 (F01 regression): zero downloaded payloads — must fail even with a
# valid signature over the manifest
echo "--- Test 10: Zero payloads fail closed ---"
ZERO_DIR="${TMPDIR}/zero-payload"
mkdir -p "${ZERO_DIR}"
cp "${WORKDIR}/SHA256SUMS.txt" "${WORKDIR}/SHA256SUMS.txt.minisig" "${ZERO_DIR}/"

if "${VERIFY_SCRIPT}" --dir "${ZERO_DIR}" --pubkey "${TEST_PUBKEY}" --checksum-only >/dev/null 2>&1; then
  bad "Test 10: zero payloads must fail"
else
  ok "Test 10: zero downloaded payloads fail closed (authenticated manifest alone is not success)"
fi

# Test 11 (F01 regression): missing required verifier tool
echo "--- Test 11: Missing required verification tool fails closed ---"
PATH_SANS_SHA="$(mktemp -d)"
for d in $(echo "${PATH}" | tr ':' ' '); do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in
      sha256sum|shasum|minisign|cosign|go) continue ;;
    esac
    ln -s "$f" "${PATH_SANS_SHA}/$b" 2>/dev/null || true
  done
done
# ONLY the sanitized dir on PATH: any tool the verifier needs (sha256sum,
# shasum, minisign, go, cosign) is absent from it — the rest of the toolkit
# is symlinked in so bash/awk/etc. still work.
if PATH="${PATH_SANS_SHA}" bash -c '"${0}" --dir "${1}" --pubkey "${2}" --checksum-only >/dev/null 2>&1' "${VERIFY_SCRIPT}" "${WORKDIR}" "${TEST_PUBKEY}"; then
  bad "Test 11: missing sha tool must fail closed"
else
  ok "Test 11: missing required verification tool fails closed"
fi

# Test 12 (F01 regression): official mode requires the sigstore bundle — a
# release directory without one must NOT produce the official banner.
echo "--- Test 12: Official mode requires sigstore bundle (absent → fail closed) ---"
if "${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" >/dev/null 2>&1; then
  bad "Test 12: official mode must fail when the release ships no sigstore bundle"
else
  ok "Test 12: official mode fails closed on missing sigstore bundle"
fi
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" > "${TMPDIR}/t12.out" 2>&1 || true
if grep -q "ALL RELEASE ASSET VERIFICATIONS PASSED" "${TMPDIR}/t12.out"; then
  bad "Test 12b: official banner must never print for an unsigned-incomplete run"
fi

# Test 13 (F01 regression): reduced-assurance mode is truthful — with
# --skip-cosign and no bundle, minisign+payloads pass but the banner must say
# REDUCED, never the official message.
echo "--- Test 13: --skip-cosign without bundle → truthful reduced-assurance label ---"
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign > "${TMPDIR}/t13.out" 2>&1 || true
if grep -q "REDUCED-ASSURANCE VERIFICATION PASSED" "${TMPDIR}/t13.out"; then
  ok "Test 13: reduced-assurance banner is truthful"
else
  bad "Test 13: --skip-cosign (no bundle) should pass with the REDUCED banner"
fi
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign > "${TMPDIR}/t13b.out" 2>&1 || true
if grep -q "ALL RELEASE ASSET VERIFICATIONS PASSED" "${TMPDIR}/t13b.out"; then
  bad "Test 13b: official banner must not print in reduced-assurance mode"
fi

# Test 14 (F01 regression): --skip-cosign while a bundle IS present must fail —
# the entitlement is only for releases that genuinely predate the bundle.
echo "--- Test 14: --skip-cosign with a present bundle fails closed ---"
BUNDLE_DIR="${TMPDIR}/with-bundle"
cp -r "${WORKDIR}" "${BUNDLE_DIR}"
echo '{"not":"a real bundle"}' > "${BUNDLE_DIR}/SHA256SUMS.txt.sigstore.json"
if "${VERIFY_SCRIPT}" --dir "${BUNDLE_DIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  bad "Test 14: --skip-cosign must fail when the release ships a bundle"
else
  ok "Test 14: skip-cosign entitlement rejected when bundle present"
fi

# Test 15 (F01 regression): missing required tool for the SIGNATURE step
# (no minisign, no go) must fail closed.
echo "--- Test 15: Missing signature verifier tool fails closed ---"
if PATH="${PATH_SANS_SHA}" bash -c '"${0}" --dir "${1}" --pubkey "${2}" --checksum-only >/dev/null 2>&1' "${VERIFY_SCRIPT}" "${WORKDIR}" "${TEST_PUBKEY}"; then
  bad "Test 15: missing minisign+go must fail closed"
else
  ok "Test 15: missing signature verification tool fails closed"
fi

# Test 16: valid complete official-release verification with a synthetic
# sigstore bundle is not possible without real cosign OIDC issuance — the
# official happy path (bundle + cosign) is covered in CI where cosign exists;
# here we assert the official banner is RESERVED (not printed in any reduced
# mode) and that the official gate fails closed without its required pieces.
echo "--- Test 16: official banner reserved (not printed in reduced modes) ---"
OFFICIAL_LEAK=0
for MODE in "--checksum-only" "--skip-cosign"; do
  "${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" ${MODE} > "${TMPDIR}/t16.out" 2>&1 || true
  if grep -q "ALL RELEASE ASSET VERIFICATIONS PASSED" "${TMPDIR}/t16.out"; then
    OFFICIAL_LEAK=1
  fi
done
if [[ "${OFFICIAL_LEAK}" == "0" ]]; then
  ok "Test 16: official banner never printed outside full official verification"
else
  bad "Test 16: official banner leaked into a reduced mode"
fi

echo ""
if [[ ${FAIL} -gt 0 ]]; then
  echo "=== ${FAIL} TEST(S) FAILED (${PASS} passed) ==="
  exit 1
fi
echo "=== ALL ${PASS} RELEASE VERIFICATION TESTS PASSED ==="
