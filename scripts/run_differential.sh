#!/usr/bin/env bash
# run_differential.sh — Cross-language differential parity harness (Go <-> TypeScript)
# Usage: ./scripts/run_differential.sh [count] [seed]

set -euo pipefail

COUNT="${1:-1000}"
SEED="${2:-1337}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO_ROOT"

echo "=== Running Differential Parity Harness (count=${COUNT}, seed=${SEED}) ==="

# 1. Generate Go vectors and write to packages/wire/testdata/diffgen-go.jsonl
echo "--- 1. Generating Go differential vectors ---"
go run ./scripts/diffgen -count="${COUNT}" -seed="${SEED}" -max-pad-len=256 -out=packages/wire/testdata/diffgen-go.jsonl

# 2. Run TypeScript consumer test (validates Go vectors, then exports TS vectors to diffgen-ts.jsonl)
echo "--- 2. Running TypeScript consumer test (Go -> TS) & generating TS vectors ---"
pnpm --filter @sendbeam/protocol test src/differential.test.ts

# 3. Run Go consumer test (validates TS vectors)
echo "--- 3. Running Go consumer test (TS -> Go) ---"
go test -v -run='^TestDifferential' ./packages/wire

echo "=== Differential parity verified across all codecs (seed=${SEED}, count=${COUNT}) ==="
