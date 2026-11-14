#!/usr/bin/env bash
# ==============================================================================
# SendBeam Release Verification Test Suite
# Tests scripts/verify-release.sh: happy paths, adversarial tamper vectors, and
# the fail-closed policy (missing provenance bundle/tools, zero payloads,
# reduced modes).
#
# The Minisign trust anchor was removed with the self-updater (SB-SIMPLIFY).
# Provenance is now asserted only by the keyless Sigstore bundle, so these
# tests fabricate a bundle file and a fake `cosign` on PATH rather than
# generating signing keys: the script's job is to demand and invoke them, and
# that contract is what is under test here.
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

# A fake cosign that succeeds. Real cosign is exercised by the release workflow
# against real OIDC identity; here we assert the script's control flow.
FAKE_BIN="${TMPDIR}/fakebin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/cosign" <<'FAKECOSIGN'
#!/usr/bin/env bash
# Minimal stand-in: accepts `verify-blob --bundle <b> ... <subject>` and exits 0.
for arg in "$@"; do
  case "${arg}" in
    verify-blob) ;;
  esac
done
exit "${FAKE_COSIGN_EXIT:-0}"
FAKECOSIGN
chmod +x "${FAKE_BIN}/cosign"

# A fake cosign that fails, for the tamper path.
mkdir -p "${TMPDIR}/failbin"
cat > "${TMPDIR}/failbin/cosign" <<'FAKEFAIL'
#!/usr/bin/env bash
echo "cosign: signature verification failed" >&2
exit 1
FAKEFAIL
chmod +x "${TMPDIR}/failbin/cosign"

# 1. Setup mock release assets
WORKDIR="${TMPDIR}/release-test"
mkdir -p "${WORKDIR}"

echo "binary linux amd64 payload content v1.6.0" > "${WORKDIR}/sendbeam-cli-linux-amd64.tar.gz"
echo "binary darwin arm64 payload content v1.6.0" > "${WORKDIR}/sendbeam-cli-darwin-arm64.tar.gz"
echo "desktop deb payload content v1.6.0" > "${WORKDIR}/sendbeam-desktop_1.6.0_amd64.deb"

(
  cd "${WORKDIR}"
  sha256sum * > SHA256SUMS.txt
  echo '{"fake":"sigstore-bundle"}' > SHA256SUMS.txt.sigstore.json
)

BUNDLE_DIR="${TMPDIR}/bundle-test"
cp -r "${WORKDIR}" "${BUNDLE_DIR}"

# Test 1: Happy path — checksum-only mode (no bundle assertion).
echo "--- Test 1: Valid artifacts, partial payloads (checksum-only) ---"
"${VERIFY_SCRIPT}" --dir "${WORKDIR}" --checksum-only >/dev/null
ok "Test 1: checksum-only happy path"

# Test 2: Tampered file payload
echo "--- Test 2: Tampered file payload ---"
CORRUPT_DIR="${TMPDIR}/corrupt-file"
cp -r "${WORKDIR}" "${CORRUPT_DIR}"
echo "CORRUPTED BYTE" >> "${CORRUPT_DIR}/sendbeam-cli-linux-amd64.tar.gz"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_DIR}" --checksum-only >/dev/null 2>&1; then
  bad "Test 2: Expected failure on tampered file payload"
else
  ok "Test 2: tampered payload rejected"
fi

# Test 3: Tampered manifest
echo "--- Test 3: Tampered checksum manifest ---"
CORRUPT_SUMS="${TMPDIR}/corrupt-sums"
cp -r "${WORKDIR}" "${CORRUPT_SUMS}"
sed -i 's/^\([a-f0-9]\{64\}\)/0000000000000000000000000000000000000000000000000000000000000000/' \
  "${CORRUPT_SUMS}/SHA256SUMS.txt"

if "${VERIFY_SCRIPT}" --dir "${CORRUPT_SUMS}" --checksum-only >/dev/null 2>&1; then
  bad "Test 3: Expected failure on tampered manifest"
else
  ok "Test 3: tampered manifest rejected"
fi

# Test 4: No payloads at all
echo "--- Test 4: Manifest with zero payloads present ---"
EMPTY_DIR="${TMPDIR}/empty"
mkdir -p "${EMPTY_DIR}"
printf '%064d  sendbeam-cli-linux-amd64.tar.gz\n' 0 > "${EMPTY_DIR}/SHA256SUMS.txt"

if "${VERIFY_SCRIPT}" --dir "${EMPTY_DIR}" --checksum-only >/dev/null 2>&1; then
  bad "Test 4: Expected failure with zero payloads"
else
  ok "Test 4: zero payloads fails closed"
fi

# Test 5: Missing payload in --strict mode
echo "--- Test 5: --strict requires every listed payload ---"
MISSING_DIR="${TMPDIR}/missing"
cp -r "${WORKDIR}" "${MISSING_DIR}"
rm "${MISSING_DIR}/sendbeam-desktop_1.6.0_amd64.deb"

if "${VERIFY_SCRIPT}" --dir "${MISSING_DIR}" --strict --checksum-only >/dev/null 2>&1; then
  bad "Test 5: Expected --strict failure on missing payload"
else
  ok "Test 5: --strict fails on missing payload"
fi

# Test 6: A missing Sigstore bundle fails closed in official mode.
# This is the SB-SIMPLIFY replacement for the removed Minisign requirement:
# with no keyless bundle there is no provenance, so the run must fail.
echo "--- Test 6: Missing provenance bundle fails closed in official mode ---"
NO_SIG_DIR="${TMPDIR}/no-bundle"
cp -r "${WORKDIR}" "${NO_SIG_DIR}"
rm "${NO_SIG_DIR}/SHA256SUMS.txt.sigstore.json"

if "${VERIFY_SCRIPT}" --dir "${NO_SIG_DIR}" >/dev/null 2>&1; then
  bad "Test 6: missing Sigstore bundle must fail closed"
else
  ok "Test 6: missing Sigstore bundle fails closed"
fi

# Test 7: --skip-cosign refuses when a bundle IS present (do not downgrade
# a release that ships provenance).
echo "--- Test 7: --skip-cosign refused when a bundle is present ---"
if "${VERIFY_SCRIPT}" --dir "${WORKDIR}" --skip-cosign >/dev/null 2>&1; then
  bad "Test 7: --skip-cosign must be refused when a bundle is present"
else
  ok "Test 7: --skip-cosign refused with bundle present"
fi

# Test 8: A failing cosign verification fails the run.
echo "--- Test 8: Failing cosign verification fails the run ---"
if PATH="${TMPDIR}/failbin:${PATH}" "${VERIFY_SCRIPT}" --dir "${BUNDLE_DIR}" >/dev/null 2>&1; then
  bad "Test 8: Expected failure when cosign verification fails"
else
  ok "Test 8: cosign failure fails closed"
fi

# Test 9: Official mode with bundle + cosign present passes and prints the
# official banner.
echo "--- Test 9: Official mode with bundle passes ---"
if PATH="${TMPDIR}/fakebin:${PATH}" "${VERIFY_SCRIPT}" --dir "${BUNDLE_DIR}" >"${TMPDIR}/t9.out" 2>&1; then
  if grep -q "ALL RELEASE ASSET VERIFICATIONS PASSED" "${TMPDIR}/t9.out"; then
    ok "Test 9: official-mode success banner"
  else
    bad "Test 9: missing official-mode banner"
  fi
else
  bad "Test 9: official mode failed with valid bundle"
fi

# Test 10: No stale Minisign surface remains in the script.
# The signer was removed at the root; the script must not still demand it.
echo "--- Test 10: no Minisign dependency in the verification script ---"
if grep -qi "minisign" "${VERIFY_SCRIPT}"; then
  bad "Test 10: verify-release.sh still references minisign"
else
  ok "Test 10: no minisign reference remains"
fi

# Test 11: no signing secret is required by the verifier.
echo "--- Test 11: no signing secret required ---"
if grep -q "MINISIGN_SECRET_KEY" "${VERIFY_SCRIPT}"; then
  bad "Test 11: verify-release.sh still reads MINISIGN_SECRET_KEY"
else
  ok "Test 11: no signing secret required"
fi

# ------------------------------------------------------------------------------
echo ""
echo "=== RESULTS: ${PASS} passed, ${FAIL} failed ==="
if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
