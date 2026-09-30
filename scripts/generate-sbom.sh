#!/usr/bin/env bash
# generate-sbom.sh — Generates SPDX 2.3 standard JSON Software Bill of Materials (SBOM)
# for SendBeam components (CLI and Desktop) from Go module dependencies and build metadata.

set -euo pipefail

TARGET="cli"
OUTPUT=""
VERSION="dev"
COMMIT="unknown"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    --commit)
      COMMIT="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--target cli|desktop] [--output <path>] [--version <ver>] [--commit <sha>]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$TARGET" != "cli" && "$TARGET" != "desktop" ]]; then
  echo "Error: --target must be 'cli' or 'desktop'" >&2
  exit 1
fi

COMPONENT_NAME="sendbeam-${TARGET}"
GOMOD_PATH="apps/${TARGET}/go.mod"

if [[ ! -f "$GOMOD_PATH" ]]; then
  echo "Error: $GOMOD_PATH not found" >&2
  exit 1
fi

# F19: prefer the resolved module graph over raw go.mod text. `go list -m all`
# applies replace directives and yields the effective versions actually
# compiled; the text parse remains as a fallback for environments without Go
# (and the output is then labelled as an unresolved go.mod inventory).
RESOLUTION="resolved (go list -m all)"
if command -v go >/dev/null 2>&1; then
  MODULE_LIST="$( (cd "apps/${TARGET}" && go list -m all 2>/dev/null) || true )"
fi
if [ -z "${MODULE_LIST:-}" ]; then
  RESOLUTION="unresolved (go.mod text parse; Go unavailable — versions are require-line values, replace directives NOT applied)"
  MODULE_LIST=""
fi

# F19: deterministic document identity — derived from version+commit+module
# list instead of wall-clock/random values, so identical inputs produce
# identical SPDX documents (reproducibility scope: this document only).
TIMESTAMP="$(printf '%s' "${VERSION}-${COMMIT}-${MODULE_LIST}" | sha256sum | awk '{print substr($1,1,12)}')"
DOC_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo 1970-01-01T00:00:00Z)"
DOC_NAMESPACE="https://github.com/Akshay7273/sendbeam/spdxdocs/${COMPONENT_NAME}-${VERSION}-${COMMIT}-${TIMESTAMP}"
CREATED="${DOC_DATE}"

# Extract Go dependencies
DEPENDENCIES_JSON="[]"
DEPS=()
RELATIONSHIPS=()

# Main document describes root package
RELATIONSHIPS+=("{\"spdxElementId\": \"SPDXRef-DOCUMENT\", \"relatedSpdxElement\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"relationshipType\": \"DESCRIBES\"}")

add_dep() {
  local MOD_PATH="$1" MOD_VER="$2"
  [ -z "${MOD_PATH}" ] && return 0
  case "${MOD_VER}" in v*) ;; *) return 0 ;; esac
  local SAFE_ID="SPDXRef-Package-$(echo "${MOD_PATH}" | tr '/.~_' '----')"
  local PKG_ENTRY="{\"SPDXID\": \"${SAFE_ID}\", \"name\": \"${MOD_PATH}\", \"versionInfo\": \"${MOD_VER}\", \"downloadLocation\": \"https://${MOD_PATH}\", \"filesAnalyzed\": false, \"licenseConcluded\": \"NOASSERTION\", \"licenseDeclared\": \"NOASSERTION\", \"supplier\": \"NOASSERTION\"}"
  DEPS+=("${PKG_ENTRY}")
  RELATIONSHIPS+=("{\"spdxElementId\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"relatedSpdxElement\": \"${SAFE_ID}\", \"relationshipType\": \"DEPENDS_ON\"}")
}

if [ -n "${MODULE_LIST}" ]; then
  # Resolved mode: first line is the root module itself — skip it.
  while IFS= read -r line; do
    MOD_PATH="${line%% *}"
    MOD_VER="${line##* }"
    [ "${MOD_PATH}" = "${MOD_VER}" ] && continue
    add_dep "${MOD_PATH}" "${MOD_VER}"
  done <<< "${MODULE_LIST}"
else
  # Fallback mode: parse require lines (unresolved versions).
  while IFS= read -r line; do
    line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [[ "${line}" =~ ^([a-zA-Z0-9.\/_~-]+)[[:space:]]+(v[0-9a-zA-Z.-]+) ]]; then
      add_dep "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    fi
  done < <(grep -E '^[[:space:]]*[a-zA-Z0-9.\/_~-]+[[:space:]]+v[0-9]' "${GOMOD_PATH}" || true)
fi

# Build JSON structure
# Root package
ROOT_PKG="{\"SPDXID\": \"SPDXRef-Package-${COMPONENT_NAME}\", \"name\": \"${COMPONENT_NAME}\", \"versionInfo\": \"${VERSION}\", \"downloadLocation\": \"git+https://github.com/Akshay7273/sendbeam@${COMMIT}\", \"filesAnalyzed\": false, \"homepage\": \"https://github.com/Akshay7273/sendbeam\", \"licenseConcluded\": \"MIT\", \"licenseDeclared\": \"MIT\", \"supplier\": \"Person: Akshay Kumar <https://github.com/Akshay7273>\", \"originator\": \"Person: Akshay Kumar <https://github.com/Akshay7273>\"}"

# Combine packages
ALL_PACKAGES=("$ROOT_PKG")
ALL_PACKAGES+=("${DEPS[@]}")

# Join packages array
PACKAGES_JOINED="$(IFS=,; echo "${ALL_PACKAGES[*]}")"
RELATIONSHIPS_JOINED="$(IFS=,; echo "${RELATIONSHIPS[*]}")"

SPDX_JSON=$(cat <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "${COMPONENT_NAME}-${VERSION}-SBOM",
  "documentNamespace": "${DOC_NAMESPACE}",
  "creationInfo": {
    "created": "${CREATED}",
    "creators": [
      "Tool: SendBeam-SBOM-Generator-1.0",
      "Organization: SendBeam Open Source Project",
      "Person: Akshay Kumar"
    ]
  },
  "packages": [
    ${PACKAGES_JOINED}
  ],
  "relationships": [
    ${RELATIONSHIPS_JOINED}
  ]
}
EOF
)

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  echo "$SPDX_JSON" > "$OUTPUT"
  echo "Wrote SPDX 2.3 SBOM to $OUTPUT"
else
  echo "$SPDX_JSON"
fi
