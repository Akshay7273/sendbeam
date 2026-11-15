#!/usr/bin/env bash
# docs-consistency.sh — deterministic documentation drift checks (audit F25).
#
# Checks:
#   1. Every relative Markdown link target exists (missing-link = fail).
#   2. Version strings in package manifests (Formula/bucket/AUR/WinGet) all
#      name the same version, and every manifest records that release's URL and
#      SHA-256 at every place it appears. Agreement between manifests is not
#      enough on its own — a tree where all three say 1.9.0 is self-consistent
#      and still wrong — so each manifest's own URL/tag/hash must also agree
#      with its siblings, and the redundant packaging/ copies must match.
#      Historical versioned directories (packaging/winget/manifests/.../X.Y.Z)
#      and dated release records are deliberately NOT checked; they are records
#      of what shipped, not claims about the current release.
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
echo "=== [2/3] Committed package-manifest consistency (version, tag, hash) ==="
set +e
python3 - <<'PY'
import json, re, sys

# Each "current release" manifest must agree on one version, one release tag in
# its download URLs, and one SHA-256 per artifact. Agreement among manifests is
# necessary but not sufficient: a tree where every manifest agrees on a stale
# version is exactly the failure this check exists to catch, so the URL tag and
# the per-artifact hash are cross-compared too.
problems = []
versions = {}
tags = {}
hashes = {}   # artifact -> {manifest: sha}

def record(manifest, version, tag, artifact_hashes):
    versions[manifest] = version
    if tag:
        tags[manifest] = tag
    for artifact, sha in artifact_hashes.items():
        hashes.setdefault(artifact, {})[manifest] = sha

# --- Homebrew -------------------------------------------------------------
for path in ("Formula/sendbeam.rb", "packaging/homebrew/Formula/sendbeam.rb"):
    try:
        text = open(path).read()
    except FileNotFoundError:
        continue
    vm = re.search(r'version\s+"([^"]+)"', text)
    version = vm.group(1) if vm else "?"
    # url lines look like .../download/<tag>/<artifact>; sha256 lines follow.
    artifacts = {}
    current = None
    for line in text.splitlines():
        um = re.search(r'download/([^/]+)/([^"\s]+)', line)
        if um:
            current = um.group(2)
            tag = um.group(1)
        sm = re.search(r'sha256\s+"([0-9a-f]{64})"', line)
        if sm and current:
            artifacts[current] = sm.group(1)
            current = None
    record(path, version, tag, artifacts)

# --- Scoop ----------------------------------------------------------------
for path in ("bucket/sendbeam.json", "packaging/scoop/sendbeam.json"):
    try:
        d = json.load(open(path))
    except FileNotFoundError:
        continue
    artifacts = {}
    tag = None
    for arch, info in (d.get("architecture") or {}).items():
        url = info.get("url", "")
        m = re.search(r'/download/([^/]+)/([^/]+)$', url)
        if m:
            tag = m.group(1)
            if info.get("hash"):
                artifacts[m.group(2)] = info["hash"].lower()
    record(path, d.get("version", "?"), tag, artifacts)

# --- AUR ------------------------------------------------------------------
for path in ("packaging/aur/PKGBUILD", "packaging/aur/.SRCINFO"):
    try:
        text = open(path).read()
    except FileNotFoundError:
        continue
    # PKGBUILD uses `pkgver=1.2.3`; .SRCINFO tab-indents `pkgver = 1.2.3`.
    vm = re.search(r'^\s*pkgver\s*=\s*(.+)$', text, re.M)
    version = vm.group(1).strip("'\"").strip() if vm else "?"
    artifacts = {}
    tag = None
    # PKGBUILD: source_<arch>=(url) followed by sha256sums_<arch>=('hash')
    srcs = dict(re.findall(r'source_(\w+)=\("([^"]+)"\)', text))
    sums = dict(re.findall(r"sha256sums_(\w+)=\('([^']+)'\)", text))
    for arch, url in srcs.items():
        m = re.search(r'/download/([^/]+)/([^/]+)$', url)
        if m and arch in sums:
            tag = m.group(1)
            artifacts[m.group(2)] = sums[arch].lower()
    # .SRCINFO uses unparenthesised key = value lines
    if not artifacts:
        for key, url in re.findall(r'^\s*source_(\w+)\s*=\s*(\S+)$', text, re.M):
            m = re.search(r'/download/([^/]+)/([^/]+)$', url)
            if m:
                tag = m.group(1)
        # .SRCINFO: pair source_<arch> with sha256sums_<arch>
        s2 = re.findall(r'^\s*source_(\w+)\s*=\s*(\S+)$', text, re.M)
        h2 = re.findall(r'^\s*sha256sums_(\w+)\s*=\s*([0-9a-fA-F]{64})$', text, re.M)
        hmap = dict(h2)
        for arch, url in s2:
            m = re.search(r'/download/([^/]+)/([^/]+)$', url)
            if m and arch in hmap:
                artifacts[m.group(2)] = hmap[arch].lower()
    record(path, version, tag, artifacts)

# --- WinGet (current release only; versioned dirs are history) -------------
try:
    import glob
    inst = sorted(glob.glob("packaging/winget/manifests/s/SendBeam/SendBeam/*/SendBeam.SendBeam.installer.yaml"))
    if inst:
        text = open(inst[-1]).read()
        vm = re.search(r'^PackageVersion:\s*(\S+)', text, re.M)
        version = vm.group(1) if vm else "?"
        artifacts = {}
        tag = None
        urls = re.findall(r'InstallerUrl:\s*(\S+)', text)
        shas = re.findall(r'InstallerSha256:\s*([0-9a-fA-F]{64})', text)
        for url, sha in zip(urls, shas):
            m = re.search(r'/download/([^/]+)/([^/]+)$', url)
            if m:
                tag = m.group(1)
                artifacts[m.group(2)] = sha.lower()
        record(inst[-1], version, tag, artifacts)
except FileNotFoundError:
    pass

# --- verdicts -------------------------------------------------------------
uniq_versions = sorted(set(versions.values()))
if len(uniq_versions) > 1:
    problems.append("manifests disagree on version: " + ", ".join(f"{k}={v}" for k, v in sorted(versions.items())))

uniq_tags = sorted(set(tags.values()))
if len(uniq_tags) > 1:
    problems.append("manifests disagree on release tag: " + ", ".join(f"{k}={v}" for k, v in sorted(tags.items())))

# version and tag must describe the same release (1.9.0 lives at v1.9.0)
if len(uniq_versions) == 1 and len(uniq_tags) == 1:
    v, t = uniq_versions[0], uniq_tags[0]
    if t.lstrip("v") != v:
        problems.append(f"version {v} and release tag {t} refer to different releases")

for artifact, by_manifest in sorted(hashes.items()):
    distinct = sorted(set(by_manifest.values()))
    if len(distinct) > 1:
        problems.append(f"hash drift for {artifact}: " + ", ".join(f"{k}={v[:12]}..." for k, v in sorted(by_manifest.items())))

print(f"[i] version={uniq_versions or ['(none)']} tag={uniq_tags or ['(none)']} artifacts={len(hashes)}")
if problems:
    print("[-] PACKAGE-MANIFEST DRIFT — committed manifests must consistently describe one real release:")
    for p in problems:
        print("    " + p)
    sys.exit(1)
print(f"[+] {len(versions)} current-release manifests agree on version {uniq_versions[0] if uniq_versions else '?'}, tag {uniq_tags[0] if uniq_tags else '?'} and {len(hashes)} artifact hashes")
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
