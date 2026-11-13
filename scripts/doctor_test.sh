#!/usr/bin/env bash
# doctor_test.sh — regression tests for scripts/doctor.sh (SB-R03).
#
# Strategy: never depend on the host's real toolchain. Each case builds a
# throwaway sandbox PATH containing:
#
#   sandbox/base/bin/  — symlinks to a whitelist of core utilities only
#                        (head, sed, grep, sort, git, ...). Nothing else.
#   sandbox/shim/bin/  — fake `go`, `node`, `pnpm`, `just`, `python3`, `cc`
#                        executables whose versions this test controls.
#
# doctor.sh is then run with PATH=sandbox/shim/bin:sandbox/base/bin, so every
# probed tool is either the controlled fake or genuinely absent. That makes
# "missing" (binary not shimmed) and "incompatible" (binary present, wrong
# version) both expressible without touching the real system, and the
# assertions hold on any machine — including CI.
#
# The base whitelist deliberately excludes cc/gcc/clang, go, node, pnpm, just,
# python3 and pkg-config: if a case does not shim a required tool, doctor.sh
# must observe it as missing. (An earlier revision inherited the real /usr/bin
# and silently found the host's cc, which invalidated a case.)
#
# Exit: 0 = all cases passed; 1 = at least one assertion failed.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCTOR="${ROOT_DIR}/scripts/doctor.sh"

if [ ! -f "${DOCTOR}" ]; then
  echo "FATAL: script under test not found: ${DOCTOR}" >&2
  exit 1
fi

failures=0
cases=0

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

# ---------------------------------------------------------------------------
# Sandbox construction
# ---------------------------------------------------------------------------

# Base utilities doctor.sh and this test legitimately need. Symlinked from the
# host into an isolated directory so PATH contains nothing else.
BASE_UTILS=(
  head sed grep sort tr cat rm chmod mktemp git dirname basename
  printf uname pwd env which
)

new_sandbox() {
  local d
  d="$(mktemp -d "${tmp_root}/s.XXXXXX")"
  mkdir -p "${d}/base/bin" "${d}/shim/bin"

  local u src
  for u in "${BASE_UTILS[@]}"; do
    src="$(command -v "${u}" 2>/dev/null || true)"
    [ -n "${src}" ] && ln -s "${src}" "${d}/base/bin/${u}" 2>/dev/null
  done

  printf '%s\n' "${d}"
}

# add_shim <sandbox> <name> <output-for-version-command> [cgo-value]
add_shim() {
  local sb="$1" name="$2" out="$3" cgo="${4:-1}"
  local path="${sb}/shim/bin/${name}"
  {
    printf '#!/bin/sh\n'
    printf 'if [ "$1" = "env" ] && [ "$2" = "CGO_ENABLED" ]; then echo "%s"; exit 0; fi\n' "${cgo}"
    printf 'echo %s\n' "$(printf '%q' "${out}")"
    printf 'exit 0\n'
  } >"${path}"
  chmod +x "${path}"
}

# A complete set of shims at the pinned/expected versions.
add_good_toolchain() {
  local sb="$1"
  add_shim "${sb}" go "go version go1.25.14 linux/amd64"
  add_shim "${sb}" node "v22.23.5"
  add_shim "${sb}" pnpm "11.20.0"
  add_shim "${sb}" just "just 1.59.0"
  add_shim "${sb}" python3 "Python 3.12.3"
  add_shim "${sb}" cc "cc (Ubuntu 13.3.0) 13.3.0"
}

# run_doctor <sandbox> — runs doctor with the fully isolated PATH.
# Result lands in ${DOCTOR_OUT}; returns doctor's exit code.
run_doctor() {
  local sb="$1"
  local isolated="${sb}/shim/bin:${sb}/base/bin"
  DOCTOR_OUT="$(PATH="${isolated}" /bin/bash "${DOCTOR}" 2>&1)"
  return $?
}

# assert_row <label> <output> <expect-status> <row-name>
assert_row() {
  local label="$1" out="$2" expect="$3" row="$4" actual
  actual="$(printf '%s\n' "${out}" | sed -n "s/^  \\(PASS\\|WARN\\|FAIL\\)  ${row} .*/\\1/p" | head -n 1)"
  if [ -z "${actual}" ]; then
    echo "    ${label}: row '${row}' missing from output" >&2
    return 1
  fi
  if [ "${actual}" != "${expect}" ]; then
    echo "    ${label}: row '${row}' was ${actual}, expected ${expect}" >&2
    return 1
  fi
  return 0
}

expect_exit() {
  local label="$1" want="$2" got="$3"
  if [ "${want}" = "${got}" ]; then return 0; fi
  echo "    ${label}: exit ${got}, expected ${want}" >&2
  return 1
}

case_pass() { cases=$((cases + 1)); printf 'ok %2d - %s\n' "${cases}" "$1"; }
case_fail() {
  cases=$((cases + 1)); failures=$((failures + 1))
  printf 'not ok %2d - %s\n' "${cases}" "$1"
  printf '%s\n' "${DOCTOR_OUT:-}" | sed 's/^/      | /' >&2
}

# ---------------------------------------------------------------------------
# Case 1: complete, compatible toolchain -> exit 0, required rows PASS
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
run_doctor "${sb}"; rc=$?
if expect_exit case1 0 "${rc}" &&
  assert_row case1 "${DOCTOR_OUT}" PASS go &&
  assert_row case1 "${DOCTOR_OUT}" PASS node &&
  assert_row case1 "${DOCTOR_OUT}" PASS pnpm &&
  assert_row case1 "${DOCTOR_OUT}" PASS just &&
  assert_row case1 "${DOCTOR_OUT}" PASS "c compiler (cgo)" &&
  assert_row case1 "${DOCTOR_OUT}" PASS CGO_ENABLED; then
  case_pass "compatible toolchain: exit 0, required rows PASS"
else
  case_fail "compatible toolchain: exit 0, required rows PASS"
fi

# ---------------------------------------------------------------------------
# Case 2: Go missing -> FAIL go, exit 1
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
rm -f "${sb}/shim/bin/go"
run_doctor "${sb}"; rc=$?
if expect_exit case2 1 "${rc}" && assert_row case2 "${DOCTOR_OUT}" FAIL go; then
  case_pass "missing go: FAIL go, exit 1"
else
  case_fail "missing go: FAIL go, exit 1"
fi

# ---------------------------------------------------------------------------
# Case 3: Node too old (v20 < 22) -> FAIL node, exit 1
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
add_shim "${sb}" node "v20.20.2"
run_doctor "${sb}"; rc=$?
if expect_exit case3 1 "${rc}" && assert_row case3 "${DOCTOR_OUT}" FAIL node; then
  case_pass "incompatible node (v20): FAIL node, exit 1"
else
  case_fail "incompatible node (v20): FAIL node, exit 1"
fi

# ---------------------------------------------------------------------------
# Case 4: Go too old (1.23) -> FAIL go, exit 1
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
add_shim "${sb}" go "go version go1.23.2 linux/amd64"
run_doctor "${sb}"; rc=$?
if expect_exit case4 1 "${rc}" && assert_row case4 "${DOCTOR_OUT}" FAIL go; then
  case_pass "incompatible go (1.23): FAIL go, exit 1"
else
  case_fail "incompatible go (1.23): FAIL go, exit 1"
fi

# ---------------------------------------------------------------------------
# Case 5: pnpm missing -> FAIL pnpm, exit 1
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
rm -f "${sb}/shim/bin/pnpm"
run_doctor "${sb}"; rc=$?
if expect_exit case5 1 "${rc}" && assert_row case5 "${DOCTOR_OUT}" FAIL pnpm; then
  case_pass "missing pnpm: FAIL pnpm, exit 1"
else
  case_fail "missing pnpm: FAIL pnpm, exit 1"
fi

# ---------------------------------------------------------------------------
# Case 6: pnpm newer than pin -> WARN pnpm, exit 0
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
add_shim "${sb}" pnpm "12.18.0"
run_doctor "${sb}"; rc=$?
if expect_exit case6 0 "${rc}" && assert_row case6 "${DOCTOR_OUT}" WARN pnpm; then
  case_pass "pnpm newer than pin: WARN pnpm, exit 0"
else
  case_fail "pnpm newer than pin: WARN pnpm, exit 0"
fi

# ---------------------------------------------------------------------------
# Case 7: no C compiler -> FAIL cgo row, exit 1
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
rm -f "${sb}/shim/bin/cc" "${sb}/shim/bin/gcc" "${sb}/shim/bin/clang"
run_doctor "${sb}"; rc=$?
if expect_exit case7 1 "${rc}" && assert_row case7 "${DOCTOR_OUT}" FAIL "c compiler (cgo)"; then
  case_pass "missing c compiler: FAIL cgo row, exit 1"
else
  case_fail "missing c compiler: FAIL cgo row, exit 1"
fi

# ---------------------------------------------------------------------------
# Case 8: CGO_ENABLED=0 -> FAIL, exit 1 (race detector unavailable)
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
add_shim "${sb}" go "go version go1.25.14 linux/amd64" 0
run_doctor "${sb}"; rc=$?
if expect_exit case8 1 "${rc}" && assert_row case8 "${DOCTOR_OUT}" FAIL CGO_ENABLED; then
  case_pass "CGO_ENABLED=0: FAIL (race needs cgo), exit 1"
else
  case_fail "CGO_ENABLED=0: FAIL (race needs cgo), exit 1"
fi

# ---------------------------------------------------------------------------
# Case 9: optional golangci-lint absent -> WARN, exit 0
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
run_doctor "${sb}"; rc=$?
if expect_exit case9 0 "${rc}" && assert_row case9 "${DOCTOR_OUT}" WARN golangci-lint; then
  case_pass "optional golangci-lint absent: WARN, exit 0"
else
  case_fail "optional golangci-lint absent: WARN, exit 0"
fi

# ---------------------------------------------------------------------------
# Case 10: doctor.sh must not mutate the working tree (read-only contract)
# ---------------------------------------------------------------------------
sb="$(new_sandbox)"; add_good_toolchain "${sb}"
before="$(cd "${ROOT_DIR}" && PATH="${sb}/base/bin" git status --porcelain 2>/dev/null | sort)"
run_doctor "${sb}" >/dev/null 2>&1
after="$(cd "${ROOT_DIR}" && PATH="${sb}/base/bin" git status --porcelain 2>/dev/null | sort)"
if [ "${before}" = "${after}" ]; then
  case_pass "doctor.sh does not mutate the working tree"
else
  case_fail "doctor.sh does not mutate the working tree"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n%d case(s), %d failure(s)\n' "${cases}" "${failures}"
[ "${failures}" -eq 0 ] || exit 1
exit 0
