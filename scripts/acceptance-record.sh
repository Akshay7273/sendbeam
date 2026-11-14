#!/usr/bin/env bash
# acceptance-record.sh — SB-R10 non-secret acceptance evidence recorder.
#
# Records installed-app / physical-network acceptance rows as JSONL with
# stable identifiers, validates them, and renders a readable report for
# docs/RELEASE-v2.3-acceptance.md.
#
# Contract:
#   * READ-ONLY on the world. Writes ONLY the evidence file you name.
#   * Collects no tokens, keys, passwords, real user files, or any secret —
#     the schema has no place to put them and validation rejects unknown keys.
#   * Distinguishes PASS / FAIL / BLOCKED / NOT RUN / NOT APPLICABLE.
#   * REJECTS fabricated evidence: a PASS row without complete provenance
#     (os, arch, artifact sha256, executable version, source sha, operator,
#     timestamp, evidence reference) fails validation and can never reach
#     the report as PASS. This is the anti-fabrication gate.
#
# Usage:
#   acceptance-record.sh record   <file.jsonl> <row-id> <result> [key=value ...]
#   acceptance-record.sh validate <file.jsonl>
#   acceptance-record.sh report   <file.jsonl>
#
# Row results and required fields:
#   PASS           os arch artifact-sha exe-version source-sha operator
#                  timestamp evidence [digest mode network]
#   FAIL           os arch source-sha operator timestamp evidence reason
#   BLOCKED        reason           (why blocked, what is missing)
#   NOT RUN        reason
#   NOT APPLICABLE reason
#
# Exit: 0 ok; 1 validation failure; 2 usage/missing tooling.

set -uo pipefail

have() { command -v "$1" >/dev/null 2>&1; }
for tool in python3; do
  if ! have "${tool}"; then
    echo "BLOCKED: required tool '${tool}' missing" >&2
    exit 2
  fi
done

usage() {
  cat >&2 <<'U'
usage:
  acceptance-record.sh record   <file.jsonl> <row-id> <result> [key=value ...]
  acceptance-record.sh validate <file.jsonl>
  acceptance-record.sh report   <file.jsonl>
results: PASS | FAIL | BLOCKED | NOT RUN | NOT APPLICABLE
keys:    os arch artifact-sha exe-version source-sha operator timestamp
         evidence digest mode network reason
U
  exit 2
}

VALIDATE_ROWTABLE() {
  python3 - "$1" <<'PY'
import json, re, sys

RESULTS = ("PASS", "FAIL", "BLOCKED", "NOT RUN", "NOT APPLICABLE")
ALLOWED_KEYS = {
    "os", "arch", "artifact-sha", "exe-version", "source-sha", "operator",
    "timestamp", "evidence", "digest", "mode", "network", "reason",
}
SHA64 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")  # git commit sha
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
ROWID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")

rows = []
with open(sys.argv[1], encoding="utf-8") as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"row {lineno}: invalid JSON: {e}")
            sys.exit(1)
        rows.append((lineno, row))

errors = []
seen = {}
for lineno, row in rows:
    where = f"row {lineno} ({row.get('id', '?')})"
    if not isinstance(row, dict):
        errors.append(f"{where}: not an object")
        continue
    rid = row.get("id", "")
    result = row.get("result", "")
    if not ROWID.match(rid or ""):
        errors.append(f"{where}: invalid row id {rid!r}")
    if rid in seen:
        errors.append(f"{where}: duplicate id (first at row {seen[rid]})")
    else:
        seen[rid] = lineno
    if result not in RESULTS:
        errors.append(f"{where}: unknown result {result!r}")
        continue
    unknown = set(row) - ALLOWED_KEYS - {"id", "result"}
    if unknown:
        errors.append(f"{where}: unknown field(s) {sorted(unknown)} — schema has no place for them (and never for secrets)")
    for k in ("artifact-sha", "digest"):
        if k in row and not SHA64.match(row[k].lower()):
            errors.append(f"{where}: {k} must be 64 lowercase hex, got {row[k]!r}")
    if "source-sha" in row and not (SHA40.match(row["source-sha"]) or SHA64.match(row["source-sha"])):
        errors.append(f"{where}: source-sha must be a git sha (40) or sha256 (64), got {row['source-sha']!r}")
    if "timestamp" in row and not TS.match(row["timestamp"]):
        errors.append(f"{where}: timestamp must be RFC3339, got {row['timestamp']!r}")

    if result == "PASS":
        required = ["os", "arch", "artifact-sha", "exe-version", "source-sha",
                    "operator", "timestamp", "evidence"]
        missing = [k for k in required if not row.get(k)]
        if missing:
            errors.append(f"{where}: FABRICATED PASS rejected — missing {missing}")
        if row.get("digest") in (None, ""):
            # a transfer row without a digest may be legitimate only if the
            # row explicitly declares mode=none (non-transfer row)
            if row.get("mode") != "none":
                errors.append(f"{where}: PASS transfer row needs a sha256 digest (or mode=none)")
    else:
        if not row.get("reason"):
            errors.append(f"{where}: {result} requires a reason")

if errors:
    for e in errors:
        print("REJECT:", e)
    sys.exit(1)
print(f"OK: {len(rows)} row(s) valid")
PY
}

case "${1:-}" in
  record)
    file="${2:-}"; id="${3:-}"; result="${4:-}"; shift 4 2>/dev/null || usage
    [ -n "${file}" ] && [ -n "${id}" ] && [ -n "${result}" ] || usage
    # Write-validate-commit: stage the row against a COPY of the file and
    # validate the whole staged result; only a valid staged file is
    # committed. A rejected row never persists (the anti-fabrication gate
    # runs BEFORE the write, not after).
    tmp_stage="$(mktemp "${TMPDIR:-/tmp}/acc-record.XXXXXX")"
    cp "$file" "$tmp_stage" 2>/dev/null || : >"$tmp_stage"
    if ! python3 - "$tmp_stage" "$id" "$result" "$@" <<'PY'
import json, sys
stage, rid, result = sys.argv[1], sys.argv[2], sys.argv[3]
row = {"id": rid, "result": result}
for kv in sys.argv[4:]:
    if "=" not in kv:
        print(f"REJECT: bad key=value {kv!r}")
        sys.exit(1)
    k, v = kv.split("=", 1)
    row[k] = v
with open(stage, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, sort_keys=True) + "\n")
PY
    then
      rm -f "$tmp_stage"; exit 1
    fi
    if ! VALIDATE_ROWTABLE "$tmp_stage"; then
      rm -f "$tmp_stage"
      echo "RECORD REJECTED: validation failed — nothing was written" >&2
      exit 1
    fi
    mv "$tmp_stage" "$file"
    echo "recorded ${id}"
    ;;
  validate)
    [ -n "${2:-}" ] || usage
    VALIDATE_ROWTABLE "$2"
    ;;
  report)
    [ -n "${2:-}" ] || usage
    # The report refuses to render an INVALID file: a fabricated/upgraded
    # row can never be presented as evidence (MU-E/MU-F gate).
    VALIDATE_ROWTABLE "$2" || {
      echo "REPORT REFUSED: the evidence file failed validation — no report" >&2
      exit 1
    }
    python3 - "$2" <<'PY'
import json, sys
from collections import Counter

rows = []
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))

order = {"PASS": 0, "FAIL": 1, "BLOCKED": 2, "NOT RUN": 3, "NOT APPLICABLE": 4}
cats = {"A": "A — artifact validation", "B": "B — harness", "C": "C — native desktop",
        "D": "D — physical network", "E": "E — evidence/doc"}
counts = Counter(r["result"] for r in rows)

print("# Acceptance evidence report")
print()
print("| Result | Rows |")
print("| --- | --- |")
for k in order:
    if counts.get(k):
        print(f"| {k} | {counts[k]} |")
print()
for r in sorted(rows, key=lambda x: (order.get(x["result"], 9), x["id"])):
    cat = r["id"].split("-", 1)[0] if "-" in r["id"] else "?"
    print(f"## {r['id']} — {r['result']} ({cats.get(cat, cat)})")
    for k in sorted(r):
        if k in ("id", "result"):
            continue
        print(f"- {k}: {r[k]}")
    print()
PY
    ;;
  *)
    usage
    ;;
esac
