#!/usr/bin/env bash
# ==============================================================================
# SendBeam Update Manifest Generator Test Suite
# Tests scripts/generate-update-manifest.go across channels and signing.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GENERATOR="${SCRIPT_DIR}/generate-update-manifest.go"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

echo "=== Running Update Manifest Generator Test Suite ==="

# 1. Setup test keypair
TEST_PUBKEY="${TMPDIR}/test-minisign.pub"
TEST_SECKEY="${TMPDIR}/test-minisign.key"
go run "${SCRIPT_DIR}/minisign.go" keygen -p "${TEST_PUBKEY}" -s "${TEST_SECKEY}" >/dev/null
TEST_SEED="$(grep -v '^untrusted' "${TEST_SECKEY}" | head -n 1)"

# 2. Setup mock release assets and SHA256SUMS.txt
ASSET_DIR="${TMPDIR}/assets"
mkdir -p "${ASSET_DIR}"

for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
  echo "dummy binary ${target}" > "${ASSET_DIR}/sendbeam-cli-${target}.tar.gz"
done
for target in windows-amd64 windows-arm64; do
  echo "dummy binary ${target}" > "${ASSET_DIR}/sendbeam-cli-${target}.zip"
done
echo "dummy desktop deb" > "${ASSET_DIR}/sendbeam-desktop_1.6.0_amd64.deb"
echo "dummy desktop appimage" > "${ASSET_DIR}/SendBeam-linux-amd64.AppImage"

(
  cd "${ASSET_DIR}"
  sha256sum * > SHA256SUMS.txt
)

# Test 1: Stable version with auto channel generates both stable.json and beta.json
echo "--- Test 1: Stable release (v1.6.0) auto channel ---"
OUT1="${TMPDIR}/out1"
MINISIGN_SECRET_KEY="${TEST_SEED}" go run "${GENERATOR}" \
  --version "1.6.0" \
  --tag "v1.6.0" \
  --channel "auto" \
  --sums "${ASSET_DIR}/SHA256SUMS.txt" \
  --dir "${ASSET_DIR}" \
  --pubkey "${TEST_PUBKEY}" \
  --out "${OUT1}" >/dev/null

test -f "${OUT1}/stable.json"
test -f "${OUT1}/stable.json.minisig"
test -f "${OUT1}/beta.json"
test -f "${OUT1}/beta.json.minisig"

# Verify Minisign signatures
go run "${SCRIPT_DIR}/minisign.go" verify -m "${OUT1}/stable.json" -p "${TEST_PUBKEY}" -x "${OUT1}/stable.json.minisig" >/dev/null
go run "${SCRIPT_DIR}/minisign.go" verify -m "${OUT1}/beta.json" -p "${TEST_PUBKEY}" -x "${OUT1}/beta.json.minisig" >/dev/null

# Verify JSON contents
python3 -c "
import json
d = json.load(open('${OUT1}/stable.json'))
assert d['version'] == '1.6.0'
assert d['channel'] == 'stable'
assert 'linux-amd64' in d['assets']
assert 'windows-amd64' in d['assets']
assert d['assets']['linux-amd64']['download_url'].startswith('https://github.com/Akshay7273/sendbeam/releases/download/v1.6.0/')
assert len(d['assets']['linux-amd64']['sha256']) == 64
"
echo "PASS [Test 1: Stable release generated and verified]"

# Test 2: Prerelease (v1.6.0-rc1) with auto channel generates ONLY beta.json
echo "--- Test 2: Prerelease (v1.6.0-rc1) auto channel ---"
OUT2="${TMPDIR}/out2"
MINISIGN_SECRET_KEY="${TEST_SEED}" go run "${GENERATOR}" \
  --version "1.6.0-rc1" \
  --tag "v1.6.0-rc1" \
  --channel "auto" \
  --sums "${ASSET_DIR}/SHA256SUMS.txt" \
  --dir "${ASSET_DIR}" \
  --pubkey "${TEST_PUBKEY}" \
  --out "${OUT2}" >/dev/null

test ! -f "${OUT2}/stable.json"
test -f "${OUT2}/beta.json"
test -f "${OUT2}/beta.json.minisig"

go run "${SCRIPT_DIR}/minisign.go" verify -m "${OUT2}/beta.json" -p "${TEST_PUBKEY}" -x "${OUT2}/beta.json.minisig" >/dev/null

python3 -c "
import json
d = json.load(open('${OUT2}/beta.json'))
assert d['version'] == '1.6.0-rc1'
assert d['channel'] == 'beta'
assert 'linux-amd64' in d['assets']
"
echo "PASS [Test 2: Prerelease correctly scoped to beta channel only]"

# Test 3: Explicit channel override
echo "--- Test 3: Explicit channel override ---"
OUT3="${TMPDIR}/out3"
MINISIGN_SECRET_KEY="${TEST_SEED}" go run "${GENERATOR}" \
  --version "1.6.0" \
  --tag "v1.6.0" \
  --channel "stable" \
  --sums "${ASSET_DIR}/SHA256SUMS.txt" \
  --dir "${ASSET_DIR}" \
  --pubkey "${TEST_PUBKEY}" \
  --out "${OUT3}" >/dev/null

test -f "${OUT3}/stable.json"
test ! -f "${OUT3}/beta.json"

echo "PASS [Test 3: Explicit channel flag respected]"

echo ""
echo "=== ALL 3 MANIFEST GENERATOR TESTS PASSED ==="
