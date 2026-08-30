#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "=== Running Package Manager Manifest Automation Tests ==="

# 1. Prepare mock SHA256SUMS.txt
MOCK_SUMS="$TMP_DIR/SHA256SUMS.txt"
HASH_DARWIN_ARM="1111111111111111111111111111111111111111111111111111111111111111"
HASH_DARWIN_AMD="2222222222222222222222222222222222222222222222222222222222222222"
HASH_LINUX_ARM="3333333333333333333333333333333333333333333333333333333333333333"
HASH_LINUX_AMD="4444444444444444444444444444444444444444444444444444444444444444"
HASH_WIN_ARM="5555555555555555555555555555555555555555555555555555555555555555"
HASH_WIN_AMD="6666666666666666666666666666666666666666666666666666666666666666"

cat <<SUMS > "$MOCK_SUMS"
$HASH_DARWIN_ARM  sendbeam-cli-darwin-arm64.tar.gz
$HASH_DARWIN_AMD  sendbeam-cli-darwin-amd64.tar.gz
$HASH_LINUX_ARM  sendbeam-cli-linux-arm64.tar.gz
$HASH_LINUX_AMD  sendbeam-cli-linux-amd64.tar.gz
$HASH_WIN_ARM  sendbeam-cli-windows-arm64.zip
$HASH_WIN_AMD  sendbeam-cli-windows-amd64.zip
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  sendbeam-cli.spdx.json
SUMS

OUT_DIR="$TMP_DIR/pkg"
TEST_VER="1.7.0"
TEST_TAG="v1.7.0"

# 2. Test generation
echo "[*] Testing manifest generation..."
go run "$SCRIPT_DIR/generate-package-manifests.go" \
  --version "$TEST_VER" \
  --tag "$TEST_TAG" \
  --sums "$MOCK_SUMS" \
  --out-dir "$OUT_DIR" \
  --sync-root=false \
  --release-date "2026-08-31"

# 3. Assert Homebrew Formula contents
echo "[*] Asserting Homebrew formula..."
BREW_FILE="$OUT_DIR/homebrew/Formula/sendbeam.rb"
test -f "$BREW_FILE"
grep -q "version \"$TEST_VER\"" "$BREW_FILE"
grep -q "url \"https://github.com/Akshay7273/sendbeam/releases/download/$TEST_TAG/sendbeam-cli-darwin-arm64.tar.gz\"" "$BREW_FILE"
grep -q "sha256 \"$HASH_DARWIN_ARM\"" "$BREW_FILE"
grep -q "sha256 \"$HASH_DARWIN_AMD\"" "$BREW_FILE"
grep -q "sha256 \"$HASH_LINUX_ARM\"" "$BREW_FILE"
grep -q "sha256 \"$HASH_LINUX_AMD\"" "$BREW_FILE"
grep -q 'bin.install "sendbeam"' "$BREW_FILE"
grep -q 'assert_match version.to_s, shell_output' "$BREW_FILE"

# 4. Assert Scoop Manifest contents
echo "[*] Asserting Scoop manifest..."
SCOOP_FILE="$OUT_DIR/scoop/sendbeam.json"
test -f "$SCOOP_FILE"
python3 -c "
import json
with open('$SCOOP_FILE') as f:
    d = json.load(f)
assert d['version'] == '$TEST_VER'
assert d['bin'] == 'sendbeam.exe'
assert d['architecture']['64bit']['hash'] == '$HASH_WIN_AMD'
assert d['architecture']['arm64']['hash'] == '$HASH_WIN_ARM'
assert '$TEST_TAG' in d['architecture']['64bit']['url']
assert 'autoupdate' in d
"

# 5. Assert WinGet Manifests contents
echo "[*] Asserting WinGet manifests..."
WINGET_VER_DIR="$OUT_DIR/winget/manifests/s/SendBeam/SendBeam/$TEST_VER"
test -f "$WINGET_VER_DIR/SendBeam.SendBeam.yaml"
test -f "$WINGET_VER_DIR/SendBeam.SendBeam.installer.yaml"
test -f "$WINGET_VER_DIR/SendBeam.SendBeam.locale.en-US.yaml"

grep -q "PackageVersion: $TEST_VER" "$WINGET_VER_DIR/SendBeam.SendBeam.yaml"
grep -q "PackageVersion: $TEST_VER" "$WINGET_VER_DIR/SendBeam.SendBeam.installer.yaml"
grep -q "InstallerSha256: $(echo $HASH_WIN_AMD | tr '[:lower:]' '[:upper:]')" "$WINGET_VER_DIR/SendBeam.SendBeam.installer.yaml"
grep -q "InstallerSha256: $(echo $HASH_WIN_ARM | tr '[:lower:]' '[:upper:]')" "$WINGET_VER_DIR/SendBeam.SendBeam.installer.yaml"
grep -q "ReleaseDate: 2026-08-31" "$WINGET_VER_DIR/SendBeam.SendBeam.installer.yaml"
grep -q "PackageVersion: $TEST_VER" "$WINGET_VER_DIR/SendBeam.SendBeam.locale.en-US.yaml"

# 6. Assert AUR PKGBUILD and .SRCINFO
echo "[*] Asserting AUR PKGBUILD and .SRCINFO..."
AUR_PKG="$OUT_DIR/aur/PKGBUILD"
AUR_SRC="$OUT_DIR/aur/.SRCINFO"
test -f "$AUR_PKG"
test -f "$AUR_SRC"

grep -q "pkgver=$TEST_VER" "$AUR_PKG"
grep -q "sha256sums_x86_64=('$HASH_LINUX_AMD')" "$AUR_PKG"
grep -q "sha256sums_aarch64=('$HASH_LINUX_ARM')" "$AUR_PKG"
grep -q 'install -Dm755 "${srcdir}/sendbeam" "${pkgdir}/usr/bin/sendbeam"' "$AUR_PKG"

grep -q "pkgver = $TEST_VER" "$AUR_SRC"
grep -q "sha256sums_x86_64 = $HASH_LINUX_AMD" "$AUR_SRC"
grep -q "sha256sums_aarch64 = $HASH_LINUX_ARM" "$AUR_SRC"

# 7. Test --validate mode (should succeed)
echo "[*] Testing --validate mode (success case)..."
go run "$SCRIPT_DIR/generate-package-manifests.go" \
  --version "$TEST_VER" \
  --tag "$TEST_TAG" \
  --sums "$MOCK_SUMS" \
  --out-dir "$OUT_DIR" \
  --sync-root=false \
  --validate

# 8. Test --validate mode fail closed on tampered checksums
echo "[*] Testing --validate mode (tampered checksum failure case)..."
BAD_SUMS="$TMP_DIR/BAD_SHA256SUMS.txt"
sed "s/$HASH_LINUX_AMD/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/" "$MOCK_SUMS" > "$BAD_SUMS"
if go run "$SCRIPT_DIR/generate-package-manifests.go" \
  --version "$TEST_VER" \
  --tag "$TEST_TAG" \
  --sums "$BAD_SUMS" \
  --out-dir "$OUT_DIR" \
  --sync-root=false \
  --validate >/dev/null 2>&1; then
  echo "[-] ERROR: validation should have failed on corrupted checksums!" >&2
  exit 1
fi
echo "[+] Validation correctly failed closed on tampered checksum."

# 9. Test missing asset hash fail closed
echo "[*] Testing missing asset hash failure case..."
INCOMPLETE_SUMS="$TMP_DIR/INCOMPLETE_SHA256SUMS.txt"
grep -v "sendbeam-cli-windows-arm64.zip" "$MOCK_SUMS" > "$INCOMPLETE_SUMS"
if go run "$SCRIPT_DIR/generate-package-manifests.go" \
  --version "$TEST_VER" \
  --tag "$TEST_TAG" \
  --sums "$INCOMPLETE_SUMS" \
  --out-dir "$OUT_DIR" \
  --sync-root=false >/dev/null 2>&1; then
  echo "[-] ERROR: generation should have failed on incomplete checksum manifest!" >&2
  exit 1
fi
echo "[+] Generator correctly failed closed on missing hash."

# 10. Simulated installer / binary smoke test
echo "[*] Testing simulated package installation workflows..."
MOCK_INSTALL_DIR="$TMP_DIR/installed"
mkdir -p "$MOCK_INSTALL_DIR/bin" "$MOCK_INSTALL_DIR/share/licenses/sendbeam-bin"

# Build actual sendbeam binary to test realistic execution
go build -ldflags "-X main.Version=$TEST_VER" -o "$TMP_DIR/sendbeam" "$ROOT_DIR/apps/cli/cmd/sendbeam"

# Simulate Homebrew install
cp "$TMP_DIR/sendbeam" "$MOCK_INSTALL_DIR/bin/sendbeam"
INSTALLED_VER=$("$MOCK_INSTALL_DIR/bin/sendbeam" --version)
echo "Homebrew smoke version output: $INSTALLED_VER"
echo "$INSTALLED_VER" | grep -q "$TEST_VER"

# Simulate AUR install
install -Dm755 "$TMP_DIR/sendbeam" "$MOCK_INSTALL_DIR/usr/bin/sendbeam"
install -Dm644 "$ROOT_DIR/LICENSE" "$MOCK_INSTALL_DIR/usr/share/licenses/sendbeam-bin/LICENSE"
test -x "$MOCK_INSTALL_DIR/usr/bin/sendbeam"
test -f "$MOCK_INSTALL_DIR/usr/share/licenses/sendbeam-bin/LICENSE"
INSTALLED_AUR_VER=$("$MOCK_INSTALL_DIR/usr/bin/sendbeam" version)
echo "AUR smoke version output: $INSTALLED_AUR_VER"
echo "$INSTALLED_AUR_VER" | grep -q "$TEST_VER"

echo "=== All Package Manager Manifest Automation Tests Passed Successfully! ==="
