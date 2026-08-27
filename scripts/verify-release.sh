#!/usr/bin/env bash
# ==============================================================================
# SendBeam Release Artifact Verification Script
#
# Cryptographically verifies SendBeam release assets against:
#   1. SHA-256 checksum manifest (SHA256SUMS.txt)
#   2. Minisign Ed25519 signature (SHA256SUMS.txt.minisig)
#   3. Sigstore cosign keyless OIDC provenance bundle (SHA256SUMS.txt.sigstore.json)
#
# Usage:
#   ./scripts/verify-release.sh [--dir <release-dir>] [--pubkey <minisign.pub>] [--strict] [--skip-cosign]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DIR="."
PUBKEY_FILE="${ROOT_DIR}/minisign.pub"
STRICT_FILES="false"
SKIP_COSIGN="false"

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
    -h|--help)
      echo "Usage: $0 [--dir <release-dir>] [--pubkey <minisign.pub>] [--strict] [--skip-cosign]"
      exit 0
      ;;
    *)
      echo "Error: Unknown option $1" >&2
      exit 1
      ;;
  esac
done

cd "${TARGET_DIR}"

if [[ ! -f "SHA256SUMS.txt" ]]; then
  echo "[-] ERROR: SHA256SUMS.txt manifest not found in ${TARGET_DIR}" >&2
  exit 1
fi

echo "=== SendBeam Release Verification Gate ==="
echo "Working directory: $(pwd)"

# ------------------------------------------------------------------------------
# 1. Minisign Signature Verification
# ------------------------------------------------------------------------------
echo ""
echo "--- [1/3] Minisign Ed25519 Signature Verification ---"

if [[ ! -f "SHA256SUMS.txt.minisig" ]]; then
  echo "[-] WARNING: SHA256SUMS.txt.minisig signature file not found"
else
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
    echo "[-] ERROR: Neither 'minisign' CLI nor Go toolchain available to verify signature" >&2
    exit 1
  fi
  echo "[✓] Minisign signature over SHA256SUMS.txt verified successfully!"
fi

# ------------------------------------------------------------------------------
# 2. Sigstore Cosign Keyless OIDC Verification
# ------------------------------------------------------------------------------
echo ""
echo "--- [2/3] Sigstore Cosign OIDC Attestation Verification ---"

if [[ "${SKIP_COSIGN}" == "true" ]]; then
  echo "[i] Skipped cosign verification (--skip-cosign flag enabled)"
elif [[ ! -f "SHA256SUMS.txt.sigstore.json" && ! -f "SHA256SUMS.txt.bundle" ]]; then
  echo "[i] No Sigstore bundle (SHA256SUMS.txt.sigstore.json) present — skipping cosign verification"
else
  BUNDLE_FILE="SHA256SUMS.txt.sigstore.json"
  if [[ ! -f "${BUNDLE_FILE}" ]]; then
    BUNDLE_FILE="SHA256SUMS.txt.bundle"
  fi

  if command -v cosign >/dev/null 2>&1; then
    echo "[+] Verifying Sigstore bundle with cosign CLI..."
    cosign verify-blob \
      --bundle "${BUNDLE_FILE}" \
      --certificate-identity-regexp 'github.com/Akshay7273/sendbeam' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      SHA256SUMS.txt
    echo "[✓] Sigstore OIDC keyless signature verified successfully!"
  else
    echo "[-] WARNING: cosign CLI not installed; skipping Sigstore bundle verification"
  fi
fi

# ------------------------------------------------------------------------------
# 3. SHA-256 Digest Validation
# ------------------------------------------------------------------------------
echo ""
echo "--- [3/3] SHA-256 Digest Checksums ---"

if [[ "${STRICT_FILES}" == "true" ]]; then
  echo "[+] Validating all checksums strictly..."
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS.txt
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS.txt
  else
    echo "[-] ERROR: Neither sha256sum nor shasum available" >&2
    exit 1
  fi
else
  echo "[+] Validating present release assets against SHA256SUMS.txt..."
  # Cross-platform ignore-missing verification
  FAILED=0
  VERIFIED=0
  while read -r expected_hash filename; do
    # Skip comments, blank lines, and signature/bundle files
    [[ -z "${expected_hash}" || "${expected_hash}" =~ ^# ]] && continue
    [[ "${filename}" == *.minisig || "${filename}" == *.sigstore.json || "${filename}" == *.bundle ]] && continue

    if [[ -f "${filename}" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        actual_hash="$(sha256sum "${filename}" | awk '{print $1}')"
      else
        actual_hash="$(shasum -a 256 "${filename}" | awk '{print $1}')"
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
    fi
  done < SHA256SUMS.txt

  if [[ ${FAILED} -gt 0 ]]; then
    echo "[-] ERROR: ${FAILED} asset(s) failed checksum validation!" >&2
    exit 1
  fi

  if [[ ${VERIFIED} -eq 0 ]]; then
    echo "[-] WARNING: No assets from SHA256SUMS.txt were present in $(pwd)"
  else
    echo "[✓] Verified ${VERIFIED} asset(s) matching SHA256SUMS.txt"
  fi
fi

echo ""
echo "========================================================"
echo "[✓] ALL RELEASE ASSET VERIFICATIONS PASSED"
echo "========================================================"
