#!/usr/bin/env bash
# ==============================================================================
# SendBeam Release Artifact Verification Script
#
# Cryptographically verifies SendBeam release artifacts against:
#   1. SHA-256 checksum manifest (SHA256SUMS.txt)
#   2. Minisign Ed25519 signature over that manifest (SHA256SUMS.txt.minisig)
#   3. Sigstore cosign keyless OIDC bundle (SHA256SUMS.txt.sigstore.json)
#
# Modes
#   (default)  official — full verification: minisign signature REQUIRED,
#              cosign bundle REQUIRED (unless the bundle file is genuinely
#              absent from the release, which is reported as reduced
#              assurance and fails the run), at least one payload verified.
#   --skip-cosign
#              Skip cosign verification only for releases that predate the
#              sigstore bundle. The run is labelled REDUCED ASSURANCE and the
#              final banner says exactly that — never the official-release
#              success message.
#   --checksum-only
#              Development/partial-download helper: authenticate the manifest
#              (minisign REQUIRED) and verify whichever payloads are present;
#              at least one payload must verify. Reduces payload completeness
#              guarantees only — the manifest is still authenticated. Labelled
#              CHECKSUM-ONLY.
#   --strict   Payload completeness: every file listed in SHA256SUMS.txt must
#              be present and match. Orthogonal to signature policy: strict
#              alone never means "verified".
#
# Exit codes: 0 = the labelled mode fully passed; 1 = any required check
# failed, was skipped without entitlement, or zero payloads verified.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DIR="."
PUBKEY_FILE="${ROOT_DIR}/minisign.pub"
STRICT_FILES="false"
SKIP_COSIGN="false"
CHECKSUM_ONLY="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir|-d)
      TARGET_DIR="$2"
      shift 2
      ;;
    --pubkey|-p)
      PUBKEY_FILE="$2"
      shift 2
      ;;
    --strict)
      STRICT_FILES="true"
      shift
      ;;
    --skip-cosign)
      SKIP_COSIGN="true"
      shift
      ;;
    --checksum-only)
      CHECKSUM_ONLY="true"
      shift
      ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,3\}//'
      exit 0
      ;;
    *)
      echo "Error: Unknown option $1" >&2
      echo "Usage: $0 [--dir <release-dir>] [--pubkey <minisign.pub>] [--strict] [--skip-cosign] [--checksum-only]" >&2
      exit 1
      ;;
  esac
done

if [[ "${PUBKEY_FILE}" != /* ]]; then
  PUBKEY_FILE="$(pwd)/${PUBKEY_FILE}"
fi
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="$(pwd)/${TARGET_DIR}"
fi

cd "${TARGET_DIR}"

if [[ ! -f "SHA256SUMS.txt" ]]; then
  echo "[-] ERROR: SHA256SUMS.txt manifest not found in ${TARGET_DIR}" >&2
  exit 1
fi

# Mode label — printed in the final banner. The official-release banner is
# reserved for a run with no reduced-assurance entitlements.
MODE_LABEL="OFFICIAL RELEASE (full cryptographic verification)"
if [[ "${CHECKSUM_ONLY}" == "true" ]]; then
  MODE_LABEL="CHECKSUM-ONLY (authenticated manifest; payload completeness NOT asserted)"
elif [[ "${SKIP_COSIGN}" == "true" ]]; then
  MODE_LABEL="REDUCED ASSURANCE (sigstore bundle verification skipped by request)"
fi

echo "=== SendBeam Release Verification Gate ==="
echo "Working directory: $(pwd)"
echo "Mode: ${MODE_LABEL}"

# ------------------------------------------------------------------------------
# 1. Minisign Signature Verification — REQUIRED in every mode
# ------------------------------------------------------------------------------
echo ""
echo "--- [1/3] Minisign Ed25519 Signature Verification (required) ---"

MINISIGN_VERIFIED="false"
if [[ ! -f "SHA256SUMS.txt.minisig" ]]; then
  echo "[-] ERROR: SHA256SUMS.txt.minisig signature file not found." >&2
  echo "    A checksum manifest without its signature cannot be authenticated;" >&2
  echo "    refusing to verify (fail closed)." >&2
  exit 1
fi

if [[ ! -f "${PUBKEY_FILE}" ]]; then
  echo "[-] ERROR: Minisign public key file not found at ${PUBKEY_FILE}" >&2
  exit 1
fi

if command -v minisign >/dev/null 2>&1; then
  echo "[+] Verifying with native minisign CLI..."
  minisign -Vm SHA256SUMS.txt -p "${PUBKEY_FILE}"
elif command -v go >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/scripts/minisign.go" ]]; then
  echo "[+] Verifying with Go minisign tool..."
  go run "${ROOT_DIR}/scripts/minisign.go" verify -m SHA256SUMS.txt -p "${PUBKEY_FILE}" -x SHA256SUMS.txt.minisig
else
  echo "[-] ERROR: Neither 'minisign' CLI nor Go toolchain available to verify the signature." >&2
  echo "    Required verification could not be completed; failing closed." >&2
  exit 1
fi
MINISIGN_VERIFIED="true"
echo "[✓] Minisign signature over SHA256SUMS.txt verified successfully!"

# ------------------------------------------------------------------------------
# 2. Sigstore Cosign Keyless OIDC Verification — required in official mode
# ------------------------------------------------------------------------------
echo ""
echo "--- [2/3] Sigstore Cosign OIDC Attestation Verification ---"

BUNDLE_FILE=""
if [[ -f "SHA256SUMS.txt.sigstore.json" ]]; then
  BUNDLE_FILE="SHA256SUMS.txt.sigstore.json"
elif [[ -f "SHA256SUMS.txt.bundle" ]]; then
  BUNDLE_FILE="SHA256SUMS.txt.bundle"
fi

COSIGN_VERIFIED="false"
COSIGN_ABSENT="false"
if [[ "${CHECKSUM_ONLY}" == "true" ]]; then
  # Reduced payload-completeness helper: sigstore provenance is out of scope
  # for this mode and the label already says so.
  echo "[i] CHECKSUM-ONLY mode: sigstore provenance not asserted (label says so)."
elif [[ "${SKIP_COSIGN}" == "true" ]]; then
  if [[ -n "${BUNDLE_FILE}" ]]; then
    echo "[-] ERROR: --skip-cosign requested but a Sigstore bundle (${BUNDLE_FILE}) is present." >&2
    echo "    Releases that ship a bundle must be verified with it; use the" >&2
    echo "    default mode instead." >&2
    exit 1
  fi
  echo "[i] REDUCED ASSURANCE: cosign verification skipped (--skip-cosign) and no bundle ships in this release."
elif [[ -z "${BUNDLE_FILE}" ]]; then
  # No bundle in the release at all: this is a release-shape problem, not a
  # user choice. Fail closed — an official release ships its bundle.
  echo "[-] ERROR: No Sigstore bundle (SHA256SUMS.txt.sigstore.json or .bundle) present." >&2
  echo "    Official SendBeam releases always ship one; refusing to present this" >&2
  echo "    as authenticated verification (fail closed). If this is genuinely a" >&2
  echo "    pre-sigstore historical release, verify with --checksum-only and read" >&2
  echo "    its reduced-assurance label." >&2
  exit 1
elif ! command -v cosign >/dev/null 2>&1; then
  echo "[-] ERROR: cosign CLI not installed; the Sigstore bundle is present so" >&2
  echo "    required verification cannot be completed. Install cosign" >&2
  echo "    (https://docs.sigstore.dev/cosign/system_config/installation/) and" >&2
  echo "    re-run, or use --checksum-only for the labelled reduced mode." >&2
  exit 1
else
  echo "[+] Verifying Sigstore bundle with cosign CLI..."
  cosign verify-blob \
    --bundle "${BUNDLE_FILE}" \
    --certificate-identity-regexp 'github.com/Akshay7273/sendbeam' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS.txt
  COSIGN_VERIFIED="true"
  echo "[✓] Sigstore OIDC keyless signature verified successfully!"
fi

# ------------------------------------------------------------------------------
# 3. SHA-256 Digest Validation
# ------------------------------------------------------------------------------
echo ""
echo "--- [3/3] SHA-256 Digest Checksums ---"

FAILED=0
VERIFIED=0
MISSING=0

verify_one() {
  local filename="$1" expected_hash="$2"
  local actual_hash=""
  if command -v sha256sum >/dev/null 2>&1; then
    actual_hash="$(sha256sum "${filename}" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_hash="$(shasum -a 256 "${filename}" | awk '{print $1}')"
  else
    echo "[-] ERROR: Neither sha256sum nor shasum available" >&2
    exit 1
  fi
  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    echo "[-] CHECKSUM MISMATCH for ${filename}!"
    echo "    Expected: ${expected_hash}"
    echo "    Actual:   ${actual_hash}"
    FAILED=$((FAILED + 1))
  else
    echo "    [OK] ${filename}"
    VERIFIED=$((VERIFIED + 1))
  fi
}

while read -r expected_hash filename; do
  # Skip comments, blank lines, and signature/bundle files
  [[ -z "${expected_hash}" || "${expected_hash}" =~ ^# ]] && continue
  [[ "${filename}" == *.minisig || "${filename}" == *.sigstore.json || "${filename}" == *.bundle ]] && continue

  if [[ -f "${filename}" ]]; then
    verify_one "${filename}" "${expected_hash}"
  elif [[ "${STRICT_FILES}" == "true" ]]; then
    echo "[-] MISSING PAYLOAD (strict mode): ${filename}" >&2
    MISSING=$((MISSING + 1))
  fi
done < SHA256SUMS.txt

if [[ ${FAILED} -gt 0 ]]; then
  echo "[-] ERROR: ${FAILED} asset(s) failed checksum validation!" >&2
  exit 1
fi
if [[ ${MISSING} -gt 0 ]]; then
  echo "[-] ERROR: ${MISSING} payload(s) listed in SHA256SUMS.txt are missing (--strict)!" >&2
  exit 1
fi
if [[ ${VERIFIED} -eq 0 ]]; then
  echo "[-] ERROR: Zero payloads from SHA256SUMS.txt were present in $(pwd)." >&2
  echo "    A manifest alone cannot prove any artifact's integrity; refusing to" >&2
  echo "    report verification success (fail closed)." >&2
  exit 1
fi
echo "[✓] Verified ${VERIFIED} payload(s) against the authenticated manifest"

# ------------------------------------------------------------------------------
# Result — mode-labelled, never overstated
# ------------------------------------------------------------------------------
echo ""
echo "========================================================"
if [[ "${CHECKSUM_ONLY}" == "true" ]]; then
  echo "[✓] CHECKSUM-ONLY VERIFICATION PASSED"
  echo "    Manifest authenticated (minisign); ${VERIFIED} payload(s) verified."
  echo "    This is NOT full authenticated release verification:"
  echo "    payload completeness and sigstore provenance were not asserted."
elif [[ "${SKIP_COSIGN}" == "true" ]]; then
  echo "[✓] REDUCED-ASSURANCE VERIFICATION PASSED"
  echo "    Minisign OK; ${VERIFIED} payload(s) verified."
  echo "    This is NOT full authenticated release verification:"
  echo "    sigstore provenance was skipped by request."
else
  echo "[✓] ALL RELEASE ASSET VERIFICATIONS PASSED"
  echo "    Official release authenticated: minisign OK, sigstore OK,"
  echo "    ${VERIFIED} payload(s) verified against the signed manifest."
fi
echo "========================================================"
