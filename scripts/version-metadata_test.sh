#!/usr/bin/env bash
# scripts/version-metadata_test.sh
# Unit tests for authoritative version resolver (scripts/version-metadata.sh)

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${DIR}/version-metadata.sh"

test_case() {
  local ref_type="$1"
  local ref_name="$2"
  local exp_ver="$3"
  local exp_macos_short="$4"
  local exp_macos_bundle="$5"
  local exp_win_fixed="$6"
  local exp_deb="$7"
  local exp_prerelease="${8:-false}"
  local exp_display="${9:-$exp_ver}"
  local exp_signing="${10:-signed}"

  local output
  output="$(GITHUB_REF_TYPE="${ref_type}" GITHUB_REF_NAME="${ref_name}" GITHUB_SHA="9908855a5e5f9d410700eedaceb970994cd785ec" "${SCRIPT}" --stdout)"

  local ver display macos_short macos_bundle win_fixed deb is_prerelease signing_status
  ver="$(echo "${output}" | grep "^version=" | cut -d= -f2)"
  display="$(echo "${output}" | grep "^display_version=" | cut -d= -f2)"
  macos_short="$(echo "${output}" | grep "^macos_short_version=" | cut -d= -f2)"
  macos_bundle="$(echo "${output}" | grep "^macos_bundle_version=" | cut -d= -f2)"
  win_fixed="$(echo "${output}" | grep "^windows_fixed_version=" | cut -d= -f2)"
  deb="$(echo "${output}" | grep "^deb_version=" | cut -d= -f2)"
  is_prerelease="$(echo "${output}" | grep "^is_prerelease=" | cut -d= -f2)"
  signing_status="$(echo "${output}" | grep "^signing_status=" | cut -d= -f2)"

  if [ "${ver}" != "${exp_ver}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected version=${exp_ver}, got ${ver}"
    exit 1
  fi
  if [ "${display}" != "${exp_display}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected display_version=${exp_display}, got ${display}"
    exit 1
  fi
  if [ "${macos_short}" != "${exp_macos_short}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected macos_short_version=${exp_macos_short}, got ${macos_short}"
    exit 1
  fi
  if [ "${macos_bundle}" != "${exp_macos_bundle}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected macos_bundle_version=${exp_macos_bundle}, got ${macos_bundle}"
    exit 1
  fi
  if [ "${win_fixed}" != "${exp_win_fixed}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected windows_fixed_version=${exp_win_fixed}, got ${win_fixed}"
    exit 1
  fi
  if [ "${deb}" != "${exp_deb}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected deb_version=${exp_deb}, got ${deb}"
    exit 1
  fi
  if [ "${is_prerelease}" != "${exp_prerelease}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected is_prerelease=${exp_prerelease}, got ${is_prerelease}"
    exit 1
  fi
  if [ "${signing_status}" != "${exp_signing}" ]; then
    echo "FAIL [${ref_type}:${ref_name}] expected signing_status=${exp_signing}, got ${signing_status}"
    exit 1
  fi

  echo "PASS [${ref_type}:${ref_name}] => ver=${ver} (${display}), macos=${macos_short}, win=${win_fixed}, deb=${deb}, prerelease=${is_prerelease}, signing=${signing_status}"
}

echo "=== Running version-metadata test suite ==="

# 1. Exact valid release tags (vX.Y.Z)
test_case "tag" "v1.4.0" "1.4.0" "1.4.0" "1.4.0" "1.4.0.0" "1.4.0" "false" "1.4.0" "signed"
test_case "tag" "v12.3.45" "12.3.45" "12.3.45" "12.3.45" "12.3.45.0" "12.3.45" "false" "12.3.45" "signed"

# 2. Valid semver prerelease tags (vX.Y.Z-prerelease)
test_case "tag" "v1.6.0-rc1" "1.6.0-rc1" "1.6.0" "1.6.0" "1.6.0.0" "1.6.0~rc1" "true" "1.6.0-rc1" "signed"
test_case "tag" "v1.6.0-beta.2" "1.6.0-beta.2" "1.6.0" "1.6.0" "1.6.0.0" "1.6.0~beta.2" "true" "1.6.0-beta.2" "signed"

# 3. Invalid or non-conforming tags (must resolve to development)
test_case "tag" "1.4.0" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"
test_case "tag" "v1.4.0foo" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"
test_case "tag" "v1.4" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"

# 4. Branches / untagged builds (must resolve to development)
test_case "branch" "main" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"
test_case "branch" "feat/something" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"
test_case "" "" "dev" "0.0.0" "0.0.0" "0.0.0.0" "0.0.0~dev+git.9908855a5e5f" "false" "unsigned-dev" "unsigned-dev"

echo "=== All 10 version-metadata test cases passed ==="
