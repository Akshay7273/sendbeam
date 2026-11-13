#!/usr/bin/env bash
# doctor.sh — deterministic, read-only environment preflight (SB-R03).
#
# Answers one question before a contributor burns time on a failing build:
# "is this machine capable of running SendBeam's gates, and if not, what
# exactly is missing?"
#
# Contract:
#   * READ-ONLY. Probes only: `command -v`, `<tool> --version`, presence of
#     files and headers. Never installs, never downloads, never mutates the
#     working tree, never reads or prints a secret.
#   * DETERMINISTIC. The same environment always produces the same verdict;
#     no ordering depends on the shell, no network access is attempted.
#   * ACTIONABLE. Every non-PASS row names the remediation command.
#
# Status vocabulary:
#   PASS  requirement satisfied
#   WARN  capability reduced (an OPTIONAL tool is missing, or a version is
#         older than the pinned one but still usable)
#   FAIL  a REQUIRED prerequisite is missing or incompatible
#
# Exit codes:
#   0  every REQUIRED check passed (WARNs allowed)
#   1  at least one REQUIRED check failed
#   2  the doctor itself could not run (unexpected internal error)
#
# Scope note (deliberate): the desktop GUI stack (Wails, GTK4/WebKit6) is
# classified OPTIONAL for the same reason CI classifies it that way — the
# `-tags server` gates build headless and need no GUI headers. Only the
# window build requires them, and that is a developer-bench capability, not a
# prerequisite for the required checks.

set -uo pipefail

# ---------------------------------------------------------------------------
# Expected versions (single source of truth; mirrors the repository)
# ---------------------------------------------------------------------------
GO_EXPECTED_MAJOR_MINOR="1.25"    # go.work `go 1.25.0`
NODE_EXPECTED_MAJOR="22"          # package.json engines.node ">=22"
PNPM_EXPECTED="11.20.0"           # package.json packageManager
GOLANGCI_EXPECTED="2.12.2"        # ci.yml golangci-lint-action version
WAILS_MIN="3.0.0"                 # apps/desktop go.mod (v3 beta train)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail_count=0
warn_count=0

# Colour is emitted only for a real terminal, so piped output stays clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_PASS=$'\033[32m'; C_WARN=$'\033[33m'; C_FAIL=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_PASS=''; C_WARN=''; C_FAIL=''; C_OFF=''
fi

pass() { printf '  %sPASS%s  %-34s %s\n' "${C_PASS}" "${C_OFF}" "$1" "${2:-}"; }
warn() {
  printf '  %sWARN%s  %-34s %s\n' "${C_WARN}" "${C_OFF}" "$1" "${2:-}"
  warn_count=$((warn_count + 1))
}
fail() {
  printf '  %sFAIL%s  %-34s %s\n' "${C_FAIL}" "${C_OFF}" "$1" "${2:-}"
  fail_count=$((fail_count + 1))
}

section() { printf '\n%s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

# first_line <cmd...> — captured stdout's first line, never a nonzero exit.
first_line() { "$@" 2>/dev/null | head -n 1; }

# ---------------------------------------------------------------------------
# Version comparison helpers (pure bash; no external tools required)
# ---------------------------------------------------------------------------

# ver_ge A B — true when A >= B, comparing dotted numeric components.
ver_ge() {
  local a="$1" b="$2" i x y
  local -a as bs
  IFS='.' read -r -a as <<<"${a//[^0-9.]/}"
  IFS='.' read -r -a bs <<<"${b//[^0-9.]/}"
  for ((i = 0; i < ${#bs[@]}; i++)); do
    x="${as[i]:-0}"
    y="${bs[i]:-0}"
    x="${x%%[!0-9]*}"; y="${y%%[!0-9]*}"
    [ -z "$x" ] && x=0
    [ -z "$y" ] && y=0
    if ((10#$x > 10#$y)); then return 0; fi
    if ((10#$x < 10#$y)); then return 1; fi
  done
  return 0
}

# major_of <version> — leading numeric component.
major_of() {
  local v="${1//[!0-9.]/}"
  printf '%s\n' "${v%%.*}"
}

# ---------------------------------------------------------------------------
section "Repository"
# ---------------------------------------------------------------------------
if [ -f "${ROOT_DIR}/go.work" ] && [ -f "${ROOT_DIR}/package.json" ]; then
  pass "repository layout" "go.work + package.json found"
else
  fail "repository layout" "run from inside the SendBeam checkout (missing go.work/package.json)"
fi

# ---------------------------------------------------------------------------
section "Required toolchain"
# ---------------------------------------------------------------------------

# --- Go ---------------------------------------------------------------------
if have go; then
  go_raw="$(first_line go version)"                       # go version go1.25.14 linux/amd64
  go_ver="$(printf '%s' "${go_raw}" | sed -n 's/.*go\([0-9][0-9.]*\).*/\1/p')"
  if [ -z "${go_ver}" ]; then
    fail "go" "found but version unparseable: ${go_raw}"
  elif ver_ge "${go_ver}" "${GO_EXPECTED_MAJOR_MINOR}.0"; then
    pass "go" "${go_ver} (>= ${GO_EXPECTED_MAJOR_MINOR})"
  else
    fail "go" "${go_ver} < required ${GO_EXPECTED_MAJOR_MINOR} — install Go ${GO_EXPECTED_MAJOR_MINOR} (go.work pins it)"
  fi
else
  fail "go" "missing — install Go ${GO_EXPECTED_MAJOR_MINOR} and put it on PATH (go.work pins 'go ${GO_EXPECTED_MAJOR_MINOR}.0')"
fi

# --- Node -------------------------------------------------------------------
if have node; then
  node_ver="$(first_line node -v)"                        # v22.23.5
  node_major="$(major_of "${node_ver}")"
  if [ -z "${node_major}" ]; then
    fail "node" "found but version unparseable: ${node_ver}"
  elif [ "${node_major}" -ge "${NODE_EXPECTED_MAJOR}" ]; then
    pass "node" "${node_ver} (>= ${NODE_EXPECTED_MAJOR})"
  else
    fail "node" "${node_ver} < required major ${NODE_EXPECTED_MAJOR} — install Node ${NODE_EXPECTED_MAJOR} (package.json engines)"
  fi
else
  fail "node" "missing — install Node ${NODE_EXPECTED_MAJOR} (package.json engines.node '>=${NODE_EXPECTED_MAJOR}')"
fi

# --- pnpm -------------------------------------------------------------------
if have pnpm; then
  pnpm_ver="$(first_line pnpm -v)"
  if [ "${pnpm_ver}" = "${PNPM_EXPECTED}" ]; then
    pass "pnpm" "${pnpm_ver} (pinned)"
  elif ver_ge "${pnpm_ver}" "${PNPM_EXPECTED}"; then
    # Newer than pinned still resolves the workspace, but the lockfile check
    # runs with --frozen-lockfile in CI, so flag the divergence rather than
    # silently accepting a different resolver.
    warn "pnpm" "${pnpm_ver} != pinned ${PNPM_EXPECTED} — use 'corepack prepare pnpm@${PNPM_EXPECTED} --activate' for CI parity"
  else
    fail "pnpm" "${pnpm_ver} < pinned ${PNPM_EXPECTED} — run 'corepack prepare pnpm@${PNPM_EXPECTED} --activate'"
  fi
else
  fail "pnpm" "missing — enable it via 'corepack enable pnpm' (package.json packageManager pnpm@${PNPM_EXPECTED})"
fi

# --- C toolchain (cgo) ------------------------------------------------------
# Required: `just ci-test` runs the race detector, which needs cgo wherever the
# desktop package is tested. A missing C compiler makes -race fail before any
# test executes (the exact defect fixed in #289).
if have cc || have gcc || have clang; then
  cc_bin="$(command -v cc || command -v gcc || command -v clang)"
  cc_ver="$(first_line "${cc_bin}" --version)"
  pass "c compiler (cgo)" "${cc_bin} — ${cc_ver}"
else
  fail "c compiler (cgo)" "no cc/gcc/clang — the race detector needs cgo; install build-essential"
fi

if have go; then
  cgo_enabled="$(go env CGO_ENABLED 2>/dev/null)"
  if [ "${cgo_enabled}" = "1" ]; then
    pass "CGO_ENABLED" "1 (race detector available)"
  else
    fail "CGO_ENABLED" "go env CGO_ENABLED=${cgo_enabled} — 'just ci-test' runs -race, which requires cgo (export CGO_ENABLED=1)"
  fi
fi

# --- just -------------------------------------------------------------------
if have just; then
  pass "just" "$(first_line just --version)"
else
  fail "just" "missing — every documented gate ('just ci-test', 'just lint') is a just recipe"
fi

# --- python3 (frontend assembler + docs checker) ---------------------------
if have python3; then
  py_ver="$(first_line python3 --version)"
  pass "python3" "${py_ver}"
else
  fail "python3" "missing — 'just check-desktop-frontend' and scripts/docs-consistency.sh require it"
fi

# ---------------------------------------------------------------------------
section "Optional toolchain (reduced capability if absent)"
# ---------------------------------------------------------------------------

# --- golangci-lint ----------------------------------------------------------
# `just lint` degrades to `go vet` without it (the recipe says so explicitly),
# so a missing binary is a WARN, not a FAIL.
if have golangci-lint; then
  gl_raw="$(golangci-lint --version 2>/dev/null | head -n 1)"
  gl_ver="$(printf '%s' "${gl_raw}" | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')"
  if [ "${gl_ver}" = "${GOLANGCI_EXPECTED}" ]; then
    pass "golangci-lint" "${gl_ver} (CI pin)"
  elif [ -n "${gl_ver}" ]; then
    warn "golangci-lint" "${gl_ver} != CI pin ${GOLANGCI_EXPECTED} — lint verdict may differ from CI"
  else
    warn "golangci-lint" "present but version unparseable: ${gl_raw}"
  fi
else
  warn "golangci-lint" "missing — 'just lint' falls back to go vet only; install v${GOLANGCI_EXPECTED} for CI parity"
fi

# --- mkcert -----------------------------------------------------------------
# Only `just dev` / `just serve` need local TLS certs; the required checks do not.
if have mkcert; then
  pass "mkcert" "$(first_line mkcert -version) — 'just dev' TLS"
else
  warn "mkcert" "missing — 'just dev'/'just serve' will fail at the certs step (not required for CI gates)"
fi

# --- docker (container smoke) ----------------------------------------------
if have docker; then
  pass "docker" "$(first_line docker --version)"
else
  warn "docker" "missing — the container build/smoke job cannot be reproduced locally"
fi

# ---------------------------------------------------------------------------
section "Desktop GUI stack (optional — headless gates do not need it)"
# ---------------------------------------------------------------------------

wails_note="optional: only the Wails window/frontend-dev build uses it"
if have wails3 || have wails; then
  wails_bin="$(command -v wails3 2>/dev/null || command -v wails)"
  wails_raw="$(first_line "${wails_bin}" version)"
  pass "wails" "${wails_raw:-present} (${wails_bin})"
else
  warn "wails" "not installed (${wails_note}); go.mod uses github.com/wailsapp/wails/v3 ${WAILS_MIN}+"
fi

# Wails v3 on Linux links against GTK4/WebKit6 — but only for the window
# build. Detect via pkg-config where available, otherwise via header paths.
gui_missing=""
if have pkg-config; then
  for mod in gtk4 webkitgtk-6.0 libsoup-3.0; do
    pkg-config --exists "${mod}" 2>/dev/null || gui_missing="${gui_missing} ${mod}"
  done
  if [ -z "${gui_missing}" ]; then
    pass "gtk4/webkit6/libsoup3" "pkg-config modules present"
  else
    warn "gtk4/webkit6/libsoup3" "missing:${gui_missing} — install libgtk-4-dev libwebkitgtk-6.0-dev libsoup-3.0-dev for the window build"
  fi
elif [ -d /usr/include/gtk-4.0 ] && [ -d /usr/include/webkitgtk-6.0 ]; then
  pass "gtk4/webkit6 headers" "found in /usr/include"
else
  warn "gtk4/webkit6 headers" "not detected — window build unavailable (headless gates unaffected)"
fi

# ---------------------------------------------------------------------------
section "Workspace state"
# ---------------------------------------------------------------------------

if [ -d "${ROOT_DIR}/node_modules" ]; then
  pass "node_modules" "present ('pnpm install' already run)"
else
  fail "node_modules" "absent — run 'just install' (or 'pnpm install') before the JS gates"
fi

if [ -d "${ROOT_DIR}/apps/desktop/frontend/src" ] || [ -f "${ROOT_DIR}/apps/desktop/frontend/dist/index.html" ]; then
  pass "desktop frontend" "sources present (verify with 'just check-desktop-frontend')"
else
  warn "desktop frontend" "sources/dist not found — frontend determinism gate will fail"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
total_fail="${fail_count}"
total_warn="${warn_count}"

printf '\n'
if [ "${total_fail}" -gt 0 ]; then
  printf '%sFAIL%s  %d required prerequisite(s) missing or incompatible; %d warning(s).\n' \
    "${C_FAIL}" "${C_OFF}" "${total_fail}" "${total_warn}"
  printf '      Required gates (just build / just ci-test / just lint) will not pass until these are resolved.\n'
  exit 1
fi

if [ "${total_warn}" -gt 0 ]; then
  printf '%sPASS%s  all required prerequisites satisfied; %d optional warning(s).\n' \
    "${C_PASS}" "${C_OFF}" "${total_warn}"
  exit 0
fi

printf '%sPASS%s  all prerequisites satisfied; no warnings.\n' "${C_PASS}" "${C_OFF}"
exit 0
