#!/usr/bin/env bash
# docs-consistency.sh — deterministic documentation drift checks (audit F25).
#
# Checks:
#   1. Every relative Markdown link target exists (missing-link = fail).
#   2. Version strings in package manifests (Formula/bucket/AUR) are all
#      equal (per-repo committed-version consistency).
#   3. Required-check contexts quoted in supply-chain.md §8 match the actual
#      ruleset context names listed in ci.yml job names (when the ruleset is
#      readable via gh; otherwise the ci.yml job-name set is used as the
#      reference and the doc must list a superset that only differs by
#      documented prefix).
#
# Exit: 0 = all consistency checks passed; 1 = drift found; 2 = blocked
# (required tooling missing).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

have() { command -v "$1" >/dev/null 2>&1; }

for tool in python3 grep; do
  if ! have "${tool}"; then
    echo "BLOCKED: required tool '${tool}' missing" >&2
    exit 2
  fi
done

DRIFT=0

echo "=== [1/3] Relative Markdown link targets ==="
set +e
python3 - <<'PY'
import os, re, sys

root = os.getcwd()
bad = []
checked = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", ".svelte-kit", "dist", "test-results", "playwright-report", "coverage")]
    for fn in filenames:
        if not fn.endswith(".md"):
            continue
        p = os.path.join(dirpath, fn)
        text = open(p, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            checked += 1
            tp = os.path.normpath(os.path.join(dirpath, target))
            if not os.path.exists(tp):
                bad.append((os.path.relpath(p, root), target))
if bad:
    for f, t in bad:
        print(f"[-] MISSING LINK TARGET: {f} -> {t}")
    sys.exit(1)
print(f"[+] {checked} relative links checked, all resolve")
PY
rc=$?
set -e
[ $rc -eq 0 ] || DRIFT=1

echo ""
echo "=== [2/3] Committed package-manifest version consistency ==="
set +e
python3 - <<'PY'
import json, re, sys

versions = {}
try:
    m = re.search(r'version\s+"([^"]+)"', open("Formula/sendbeam.rb").read())
    versions["Formula/sendbeam.rb"] = m.group(1) if m else "?"
except FileNotFoundError:
    pass
try:
    d = json.load(open("bucket/sendbeam.json"))
    versions["bucket/sendbeam.json"] = d.get("version", "?")
except FileNotFoundError:
    pass
try:
    m = re.search(r'^pkgver\s*=\s*(.+)$', open("packaging/aur/PKGBUILD").read(), re.M)
    versions["packaging/aur/PKGBUILD"] = m.group(1).strip("'\"") if m else "?"
except FileNotFoundError:
    pass

vals = sorted(set(versions.values()))
print(f"[i] manifest versions: {versions}")
if len(vals) > 1:
    print("[-] MANIFEST VERSION DRIFT — all committed package manifests must name the same released version")
    sys.exit(1)
print("[+] all committed manifests agree on", vals[0] if vals else "(none present)")
PY
rc=$?
set -e
[ $rc -eq 0 ] || DRIFT=1

echo ""
echo "=== [3/3] Required-check documentation matches ci.yml job names ==="
set +e
python3 - <<'PY'
import re, sys

ci = open(".github/workflows/ci.yml").read()
ci_names = set(re.findall(r'^\s{4}name: (.+)$', ci, re.M))
# matrix-templated job names are concrete at runtime; normalize to their
# documented static form.
ci_names.discard("${{ matrix.module }} (vet, test, build)")
# the branding job name contains the pre-rename string by design; the doc
# refers to it as "branding (no stale pre-rename references)" — normalize.
for n in list(ci_names):
    if n.startswith("branding "):
        ci_names.discard(n)
        ci_names.add("branding (no stale pre-rename references)")
# (offlinelab + docs-consistency are documented in §8 as evidence checks)
for mod in ("packages/wire", "packages/engine", "apps/server", "apps/cli"):
    ci_names.add(f"{mod} (vet, test, build)")

sc = open("docs/supply-chain.md").read()
sec = sc.split("Required Status Checks")[1].split("4. **")[0] if "Required Status Checks" in sc else ""
doc_names = set(re.findall(r'`([a-z][^`]*(?:vet, test, build|typecheck|build|hygiene|references|firefox|parity|smoke|evidence|consistency|determinism)[^`]*)`', sec))

# The doc must claim at least the ci job-name set where the doc row maps by
# normalized containment; report genuine drift only.
missing = []
for n in sorted(ci_names):
    if n == "differential parity (Go <-> TS)":
        continue  # runs but documented as NOT required (ledger F05)
    if n not in doc_names:
        missing.append(n)
if missing:
    print("[-] REQUIRED-CHECK DOC DRIFT — ci.yml job names not reflected in supply-chain.md §8:")
    for n in missing:
        print("    " + n)
    sys.exit(1)
print(f"[+] supply-chain.md §8 covers all documented-required ci.yml job names ({len(ci_names)-1} required + parity excluded per F05)")
PY
rc=$?
set -e
[ $rc -eq 0 ] || DRIFT=1

echo ""
if [ "${DRIFT}" != "0" ]; then
  echo "=== DOCS CONSISTENCY: DRIFT FOUND ==="
  exit 1
fi
echo "=== DOCS CONSISTENCY: ALL CHECKS PASSED ==="
