#!/usr/bin/env bash
# Copyright 2026 SendBeam Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
# OSS-Fuzz build script for SendBeam (Go native fuzzing integration).
#
# When executed within Google OSS-Fuzz container environments:
#   $OUT, $SRC, and compile_go_fuzzer are provided by the container.
#
# When executed locally for validation:
#   Simulates the build by verifying all targets compile with native Go tooling.
################################################################################

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT="${OUT:-$ROOT_DIR/bin/oss-fuzz}"
mkdir -p "$OUT"

echo "==> Preparing SendBeam OSS-Fuzz binaries into $OUT..."

TARGETS=(
  # path/to/pkg FuzzTarget output_name
  "packages/wire FuzzDecodeControl fuzz_decode_control"
  "packages/wire FuzzDecodeFrameHeader fuzz_decode_frame_header"
  "packages/wire FuzzOpenSequenced fuzz_open_sequenced"
  "packages/wire FuzzValidateManifest fuzz_validate_manifest"
  "packages/wire FuzzDecodeManifestShape fuzz_decode_manifest_shape"
  "packages/wire FuzzNormalizeTransferPath fuzz_normalize_transfer_path"
  "packages/wire FuzzPaddingCodec fuzz_padding_codec"
  "packages/wire FuzzRevocationRecord fuzz_revocation_record"
  "packages/wire FuzzPairingMessage fuzz_pairing_message"
  "packages/wire FuzzTrustedAuthMessage fuzz_trusted_auth_message"
  "packages/wire FuzzDecodeJournal fuzz_decode_journal"
  "packages/wire FuzzWordsCode fuzz_words_code"
  "packages/engine/rendezvous FuzzUnmarshalMessage fuzz_unmarshal_message"
  "packages/engine/transfer FuzzDurableJournalApply fuzz_durable_journal_apply"
  "packages/engine/trust FuzzDecodeTrustRecord fuzz_decode_trust_record"
  "packages/engine/trust FuzzFileTrustStoreLoad fuzz_file_trust_store_load"
  "packages/engine/updater FuzzParseChannelManifest fuzz_parse_channel_manifest"
  "packages/engine/updater FuzzParseChecksums fuzz_parse_checksums"
  "apps/server/internal/signal FuzzClientMsg fuzz_client_msg"
  "apps/server/internal/signal FuzzServerMessageValidation fuzz_server_msg_validation"
  "apps/server/internal/signal FuzzParseTrustedProxies fuzz_parse_trusted_proxies"
  "apps/server/internal/signal FuzzClientIP fuzz_client_ip"
)

if command -v compile_go_fuzzer >/dev/null 2>&1; then
  echo "--> Detected OSS-Fuzz compile_go_fuzzer environment"
  for entry in "${TARGETS[@]}"; do
    read -r pkg target binary_name <<< "$entry"
    echo "--> Compiling $binary_name ($pkg :: $target)..."
    compile_go_fuzzer "$pkg" "$target" "$binary_name"

    # Zip seed corpus if available
    corpus_dir="$pkg/testdata/fuzz/$target"
    if [[ -d "$corpus_dir" ]]; then
      zip -j -r "$OUT/${binary_name}_seed_corpus.zip" "$corpus_dir"/* || true
    fi
  done
else
  echo "--> Running in standalone/local mode (testing fuzz binary compilation)..."
  for entry in "${TARGETS[@]}"; do
    read -r pkg target binary_name <<< "$entry"
    echo "--> Verifying compilation: $pkg :: $target"
    (cd "$pkg" && go test -c -o "$OUT/${binary_name}.test" .)
    corpus_dir="$pkg/testdata/fuzz/$target"
    if [[ -d "$corpus_dir" ]]; then
      zip -j -q -r "$OUT/${binary_name}_seed_corpus.zip" "$corpus_dir"/* 2>/dev/null || true
    fi
  done
fi

echo "==> OSS-Fuzz build complete. Artifacts written to $OUT"
