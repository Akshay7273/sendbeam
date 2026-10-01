#!/usr/bin/env python3
"""Test fixture for promote-poll_test.sh (audit F03): resolves the latest
CI attempt from a canned runs JSON (GH_RUNS_JSON). PERM_ERROR simulates an
Actions API permission failure. Prints '<id> <status> <conclusion>'."""
import json
import os
import sys

if os.environ.get("GH_STATUS") == "permerror":
    print("PERM_ERROR")
    sys.exit(0)
raw = os.environ.get("GH_RUNS_JSON", "")
if not raw.strip():
    sys.exit(0)
try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)
runs = [r for r in data.get("workflow_runs", []) if r.get("name") == "CI"]
runs.sort(key=lambda r: r["id"])
if not runs:
    sys.exit(0)
last = runs[-1]
conc = last.get("conclusion") or "pending"
print(last.get("id", ""), last.get("status", ""), conc)
