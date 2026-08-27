#!/usr/bin/env bash
# ==============================================================================
# SendBeam Release Verification Test Suite
# Tests scripts/verify-release.sh across happy paths and adversarial tamper vectors.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERIFY_SCRIPT="${SCRIPT_DIR}/verify-release.sh"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "=== Running Release Verification Test Suite ==="

# 1. Generate test keypair
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

# Test 1: Happy path verification
echo "--- Test 1: Valid release artifacts and minisign signature ---"
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${TEST_PUBKEY}" --strict --skip-cosign >/dev/null
echo "PASS [Test 1: Happy path passed]"

# Test 2: Tampered file payload
echo "--- Test 2: Tampered file payload ---"
CORRUPT_DIR="${TMPDIR}/corrupt-file"
cp -r "${WORKDIR}" "${CORRUPT_DIR}"
echo "CORRUPTED BYTE" >> "${CORRUPT_DIR}/sendbeam-cli-linux-amd64.tar.gz"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_DIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 2: Expected failure on tampered file payload]"
  exit 1
fi
echo "PASS [Test 2: Correctly rejected tampered payload]"

# Test 3: Tampered SHA256SUMS.txt
echo "--- Test 3: Tampered SHA256SUMS.txt ---"
CORRUPT_SUMS="${TMPDIR}/corrupt-sums"
cp -r "${WORKDIR}" "${CORRUPT_SUMS}"
echo "0000000000000000000000000000000000000000000000000000000000000000  fake-file.tar.gz" >> "${CORRUPT_SUMS}/SHA256SUMS.txt"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_SUMS}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 3: Expected failure on tampered SHA256SUMS.txt]"
  exit 1
fi
echo "PASS [Test 3: Correctly rejected tampered checksums manifest]"

# Test 4: Tampered signature file
echo "--- Test 4: Tampered signature file ---"
CORRUPT_SIG="${TMPDIR}/corrupt-sig"
cp -r "${WORKDIR}" "${CORRUPT_SIG}"
sed -i 's/a/b/g' "${CORRUPT_SIG}/SHA256SUMS.txt.minisig"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_SIG}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 4: Expected failure on tampered signature file]"
  exit 1
fi
echo "PASS [Test 4: Correctly rejected tampered signature]"

# Test 5: Wrong public key
echo "--- Test 5: Wrong public key ---"
WRONG_PUBKEY="${TMPDIR}/wrong-minisign.pub"
WRONG_SECKEY="${TMPDIR}/wrong-minisign.key"
go run "${SCRIPT_DIR}/minisign.go" keygen -p "${WRONG_PUBKEY}" -s "${WRONG_SECKEY}" >/dev/null

if "${VERIFY_SCRIPT}" --dir "${WORKDIR}" --pubkey "${WRONG_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 5: Expected failure on wrong public key]"
  exit 1
fi
echo "PASS [Test 5: Correctly rejected mismatched public key]"

# Test 6: Missing manifest
echo "--- Test 6: Missing SHA256SUMS.txt ---"
EMPTY_DIR="${TMPDIR}/empty"
mkdir -p "${EMPTY_DIR}"

if "${VERIFY_SCRIPT}" --dir "${EMPTY_DIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 6: Expected failure on missing SHA256SUMS.txt]"
  exit 1
fi
echo "PASS [Test 6: Correctly rejected missing manifest]"

# Test 7: Missing file in strict mode
echo "--- Test 7: Missing file in strict mode ---"
MISSING_FILE_DIR="${TMPDIR}/missing-file"
cp -r "${WORKDIR}" "${MISSING_FILE_DIR}"
rm "${MISSING_FILE_DIR}/sendbeam-desktop_1.6.0_amd64.deb"

if "${VERIFY_SCRIPT}" --dir "${MISSING_FILE_DIR}" --pubkey "${TEST_PUBKEY}" --strict --skip-cosign >/dev/null 2>&1; then
  echo "FAIL [Test 7: Expected failure on missing file with --strict]"
  exit 1
fi
echo "PASS [Test 7: Strict mode correctly rejected missing file]"

# Test 8: Partial download in non-strict mode (ignore-missing)
echo "--- Test 8: Partial download in non-strict mode ---"
"${VERIFY_SCRIPT}" --dir "${MISSING_FILE_DIR}" --pubkey "${TEST_PUBKEY}" --skip-cosign >/dev/null
echo "PASS [Test 8: Non-strict mode verified present files]"

echo ""
echo "=== ALL 8 RELEASE VERIFICATION TESTS PASSED ==="
