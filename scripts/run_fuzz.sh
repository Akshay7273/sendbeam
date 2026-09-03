#!/usr/bin/env bash
set -euo pipefail

# SendBeam Continuous Fuzzing Runner
# Usage:
#   ./scripts/run_fuzz.sh [duration] [target_name]
#   ./scripts/run_fuzz.sh smoke
# Examples:
#   ./scripts/run_fuzz.sh 10s             # Run all targets for 10 seconds each
#   ./scripts/run_fuzz.sh 1m FuzzPaddingCodec # Run FuzzPaddingCodec for 1 minute
#   ./scripts/run_fuzz.sh smoke           # Replay committed seed corpora only (fast)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FUZZ_TIME="${1:-10s}"
FILTER_TARGET="${2:-all}"

TARGETS=(
  "packages/wire:.:FuzzDecodeControl"
  "packages/wire:.:FuzzDecodeFrameHeader"
  "packages/wire:.:FuzzOpenSequenced"
  "packages/wire:.:FuzzValidateManifest"
  "packages/wire:.:FuzzDecodeManifestShape"
  "packages/wire:.:FuzzNormalizeTransferPath"
  "packages/wire:.:FuzzPaddingCodec"
  "packages/wire:.:FuzzRevocationRecord"
  "packages/wire:.:FuzzPairingMessage"
  "packages/wire:.:FuzzTrustedAuthMessage"
  "packages/wire:.:FuzzDecodeJournal"
  "packages/wire:.:FuzzWordsCode"
  "packages/engine:./rendezvous:FuzzUnmarshalMessage"
  "packages/engine:./transfer:FuzzDurableJournalApply"
  "packages/engine:./trust:FuzzDecodeTrustRecord"
  "packages/engine:./trust:FuzzFileTrustStoreLoad"
  "packages/engine:./updater:FuzzParseChannelManifest"
  "packages/engine:./updater:FuzzParseChecksums"
  "apps/server:./internal/signal:FuzzClientMsg"
  "apps/server:./internal/signal:FuzzServerMessageValidation"
  "apps/server:./internal/signal:FuzzParseTrustedProxies"
  "apps/server:./internal/signal:FuzzClientIP"
)

if [[ "$FUZZ_TIME" == "smoke" ]]; then
  echo "==> Running Fuzz Smoke Pass (Seed Corpus Replay)..."
  for entry in "${TARGETS[@]}"; do
    IFS=":" read -r mod pkg target <<< "$entry"
    if [[ "$FILTER_TARGET" != "all" && "$target" != "$FILTER_TARGET" ]]; then
      continue
    fi
    echo "--> [smoke] $mod ($pkg) :: $target"
    (cd "$mod" && go test -run="^${target}$" "$pkg")
  done
  echo "==> All fuzz smoke tests passed!"
  exit 0
fi

echo "==> Starting Fuzzing Run (Duration per target: $FUZZ_TIME)..."
for entry in "${TARGETS[@]}"; do
  IFS=":" read -r mod pkg target <<< "$entry"
  if [[ "$FILTER_TARGET" != "all" && "$target" != "$FILTER_TARGET" ]]; then
    continue
  fi
  echo "==> Fuzzing $mod ($pkg) :: $target for $FUZZ_TIME..."
  (cd "$mod" && go test -fuzz="^${target}$" -fuzztime="$FUZZ_TIME" "$pkg")
done

echo "==> Fuzzing run completed successfully with 0 crashes."
