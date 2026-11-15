#!/usr/bin/env bash
# release-preflight.sh — validate release metadata for a version that has not
# been tagged or published yet, without inventing artifacts.
#
# Usage: bash scripts/release-preflight.sh <version>   (e.g. 2.3.0)
#
# Exit: 0 = metadata ready for tagging; 1 = problems; 2 = blocked (bad args).
#
# This checks what is knowable BEFORE a tag exists:
#   - the version is valid SemVer and strictly newer than every published tag;
#   - no tag or release already claims it (a tagged version must use the
#     release workflow, not this preflight);
#   - every committed current-release manifest is either consistent with the
#     version being prepared or flagged as needing regeneration, with the
#     regeneration command printed;
#   - embedded version constants still default to "dev" so no build claims a
#     release version without ldflags;
#   - release.yml still derives version from the tag and asserts source binding.
# It deliberately does NOT:
#   - create tags, releases or artifacts;
#   - fabricate asset URLs or SHA-256 values for the unreleased version;
#   - claim that assets exist. Asset existence is only knowable after upload,
#     and verify-release.sh is the gate for that.
set -euo pipefail

VERSION="${1:-}"
if [ -z "${VERSION}" ]; then
  echo "usage: $0 <version>   (e.g. 2.3.0)" >&2
  exit 2
fi
VERSION="${VERSION#v}"
if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "[-] '${VERSION}' is not a plain X.Y.Z version" >&2
  exit 2
fi
TAG="v${VERSION}"
PROBLEMS=0
note() { echo "[-] $*"; PROBLEMS=$((PROBLEMS + 1)); }

echo "=== Release preflight for ${TAG} (no tag, no release, no artifacts created) ==="
echo ""

echo "--- [1/6] Version is strictly newer than published releases"
PUBLISHED="$(git tag --list 'v*' --sort=-v:refname | head -20)"
# Fail closed. A shallow or unfetched clone has no tags, which would make every
# ordering and duplicate-tag comparison below trivially pass. Reporting "ready"
# from an empty tag list is the same class of bug as a checker that only
# compares a file to itself.
if [ -z "${PUBLISHED}" ]; then
  echo "[-] BLOCKED: no v* tags are visible in this clone, so published-release" >&2
  echo "    ordering cannot be verified. Fetch tags first (git fetch --tags) or" >&2
  echo "    run with full history (actions/checkout fetch-depth: 0)." >&2
  exit 2
fi
if ! printf '%s' "${PUBLISHED}" | grep -Eq "^v?${VERSION//./\\.}$"; then
  echo "[+] ${VERSION} is not already tagged"
else
  note "${TAG} already exists as a tag; use the release workflow, not preflight"
fi
NEWEST="$(git tag --list 'v*' --sort=-v:refname | head -1)"
if [ -n "${NEWEST}" ]; then
  if [ "$(printf '%s\n%s\n' "${NEWEST#v}" "${VERSION}" | sort -V | tail -1)" = "${VERSION}" ] && [ "${NEWEST#v}" != "${VERSION}" ]; then
    echo "[+] ${VERSION} sorts after the newest published tag ${NEWEST}"
  else
    note "${VERSION} does not sort after the newest published tag ${NEWEST}"
  fi
fi
echo ""

echo "--- [2/6] No release object claims this version"
if command -v gh >/dev/null 2>&1; then
  if gh release view "${TAG}" >/dev/null 2>&1; then
    note "a GitHub release for ${TAG} already exists"
  else
    echo "[+] no GitHub release exists for ${TAG}"
  fi
else
  echo "[i] gh unavailable; skipped release-existence check"
fi
echo ""

echo "--- [3/6] Embedded version constants default to dev (not a release claim)"
for pair in "apps/cli/cmd/sendbeam/version.go:Version" "apps/desktop/internal/engine/service.go:ProductVersion"; do
  f="${pair%%:*}"; c="${pair##*:}"
  if [ ! -f "${f}" ]; then note "expected version file missing: ${f}"; continue; fi
  if grep -Eq "^\s*${c}\s*=\s*\"dev\"" "${f}"; then
    echo "[+] ${f}: ${c} defaults to dev (stamped by ldflags at release)"
  else
    note "${f}: ${c} does not default to dev — a local build would claim a release version"
  fi
done
echo ""

echo "--- [4/6] Current-release package manifests"
CONSISTENT=0
if bash scripts/docs-consistency.sh >/tmp/preflight-docs.log 2>&1; then
  CUR="$(grep -oE "agree on version [0-9]+\.[0-9]+\.[0-9]+" /tmp/preflight-docs.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ -n "${CUR}" ] && [ "${CUR}" = "${VERSION}" ]; then
    echo "[+] committed manifests already describe ${VERSION}"
    CONSISTENT=1
  else
    echo "[i] committed manifests still describe ${CUR:-<none>}; they are regenerated from the release's SHA256SUMS.txt by release.yml, and the manifest-update PR reconciles the tree afterwards."
    echo "    Do not hand-edit hashes for ${VERSION}: they are unknowable until the release artifacts exist."
  fi
else
  note "docs-consistency.sh reports drift in the committed manifests (see /tmp/preflight-docs.log)"
fi
echo ""

echo "--- [5/6] Tag→version derivation and source binding still enforced"
REL=".github/workflows/release.yml"
if [ -f "${REL}" ]; then
  for needle in "version-metadata.sh" "Assert source binding" "version-metadata_test.sh"; do
    if grep -q "${needle}" "${REL}"; then
      echo "[+] release.yml contains: ${needle}"
    else
      note "release.yml no longer contains '${needle}' — tag/version binding may be weakened"
    fi
  done
else
  note "release.yml missing"
fi
echo ""

echo "--- [6/6] Supply-chain protections intact"
for needle in "verify-release.sh" "attest-build-provenance" "SHA256SUMS.txt" "cosign"; do
  if grep -rq "${needle}" .github/workflows/release.yml scripts/verify-release.sh 2>/dev/null; then
    echo "[+] present: ${needle}"
  else
    note "supply-chain protection missing: ${needle}"
  fi
done
if grep -rqi "minisign" .github/workflows/release.yml 2>/dev/null; then
  note "release.yml references Minisign again (removed by SB-SIMPLIFY)"
fi
echo ""

if [ "${PROBLEMS}" -ne 0 ]; then
  echo "=== RELEASE PREFLIGHT: ${PROBLEMS} problem(s) for ${TAG} ==="
  exit 1
fi
echo "=== RELEASE PREFLIGHT: ${TAG} metadata ready (nothing tagged, published or invented) ==="
