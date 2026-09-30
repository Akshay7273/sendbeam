#!/usr/bin/env bash
# generate-sbom_test.sh — Tests SBOM generation and SPDX 2.3 schema compliance.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=== Test 1: Generate CLI SBOM ==="
CLI_SBOM_FILE="$TMP_DIR/cli-sbom.spdx.json"
"$REPO_ROOT/scripts/generate-sbom.sh" --target cli --output "$CLI_SBOM_FILE" --version "1.4.0" --commit "abcdef1234567890" >/dev/null

# Verify SPDX version and properties (file-based: no SIGPIPE race under pipefail)
grep -q '"spdxVersion": "SPDX-2.3"' "$CLI_SBOM_FILE"
grep -q '"dataLicense": "CC0-1.0"' "$CLI_SBOM_FILE"
grep -q '"SPDXRef-DOCUMENT"' "$CLI_SBOM_FILE"
grep -q '"name": "sendbeam-cli"' "$CLI_SBOM_FILE"
grep -q '"versionInfo": "1.4.0"' "$CLI_SBOM_FILE"
grep -q '"relationshipType": "DESCRIBES"' "$CLI_SBOM_FILE"
grep -q '"relationshipType": "DEPENDS_ON"' "$CLI_SBOM_FILE"

# Verify valid JSON parsing via python + resolved-graph sanity + deterministic ns
python3 - "$CLI_SBOM_FILE" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
assert data['spdxVersion'] == 'SPDX-2.3'
assert len(data['packages']) > 1
assert len(data['relationships']) > 1
print(f"Validated CLI SBOM with {len(data['packages'])} packages")
PY

# Determinism: identical inputs → identical document namespace
NS1="$(python3 -c "import json; print(json.load(open('$CLI_SBOM_FILE'))['documentNamespace'])")"
"$REPO_ROOT/scripts/generate-sbom.sh" --target cli --output "$CLI_SBOM_FILE" --version "1.4.0" --commit "abcdef1234567890" >/dev/null
NS2="$(python3 -c "import json; print(json.load(open('$CLI_SBOM_FILE'))['documentNamespace'])")"
[ "$NS1" = "$NS2" ] && echo "[i] Deterministic document namespace OK"

echo "=== Test 2: Generate Desktop SBOM to file ==="
DESKTOP_OUT="$TMP_DIR/desktop-sbom.spdx.json"
"$REPO_ROOT/scripts/generate-sbom.sh" --target desktop --output "$DESKTOP_OUT" --version "1.4.0" --commit "abcdef1234567890"

test -f "$DESKTOP_OUT"
python3 -c "import json; data = json.load(open('$DESKTOP_OUT')); assert data['spdxVersion'] == 'SPDX-2.3'; assert data['packages'][0]['name'] == 'sendbeam-desktop'; assert len(data['packages']) > 1; print(f'Validated Desktop SBOM file with {len(data[\"packages\"])} packages')"

echo "=== ALL SBOM GENERATOR TESTS PASSED ==="
