# SendBeam Installation & Quickstart Guide

This guide details how to install and run the official SendBeam CLI and Desktop clients across Linux, macOS, and Windows.

---

## 1. Package Managers (Recommended for CLI)

SendBeam CLI is available across popular native package managers with zero external hosting cost and automated verification against the signed release manifest:

### A. Homebrew (macOS & Linux)

Install the `sendbeam` CLI formula on macOS (Apple Silicon `arm64` and Intel `x86_64`) or Linux:

```bash
# Tap the SendBeam repository and install
brew tap sendbeam/sendbeam https://github.com/Akshay7273/sendbeam
brew install sendbeam

# Or in a single command
brew install sendbeam/sendbeam/sendbeam

# Upgrade to latest release
brew upgrade sendbeam
```

### B. Scoop (Windows)

Install `sendbeam` CLI on Windows using the official Scoop bucket:

```powershell
# Add the SendBeam bucket
scoop bucket add sendbeam https://github.com/Akshay7273/sendbeam

# Install sendbeam
scoop install sendbeam

# Upgrade
scoop update sendbeam
```

### C. WinGet (Windows)

Install `sendbeam` CLI via the Windows Package Manager:

```powershell
# Install SendBeam portable CLI
winget install --id SendBeam.SendBeam

# Upgrade
winget upgrade --id SendBeam.SendBeam
```

### D. Arch Linux (AUR)

Install the pre-compiled binary package `sendbeam-bin` from the Arch User Repository:

```bash
# Using yay
yay -S sendbeam-bin

# Using paru
paru -S sendbeam-bin
```

---

## 2. Linux Installation

SendBeam offers multiple packaging formats for Linux: Debian packages (`.deb`), portable AppImages, and standalone CLI archives.

### A. Desktop Application

#### Option 1: Debian / Ubuntu Package (`.deb`)

```bash
# Download and install the Debian package
sudo dpkg -i sendbeam-desktop_<version>_amd64.deb

# If any dependencies are missing:
sudo apt-get install -f
```

This installs `sendbeam-desktop` to `/usr/bin/sendbeam-desktop`, registers desktop menu entries with icons, and configures file associations.

#### Option 2: Portable AppImage

The AppImage runs on any modern Linux distribution without installation:

```bash
# Make the AppImage executable
chmod +x SendBeam-linux-amd64.AppImage

# Launch SendBeam Desktop
./SendBeam-linux-amd64.AppImage
```

---

### B. CLI Terminal Client

```bash
# Extract the archive
tar -xzf sendbeam-cli-linux-amd64.tar.gz

# Install to /usr/local/bin
sudo install -m 755 sendbeam /usr/local/bin/sendbeam

# Verify installation
sendbeam version
```

---

## 3. macOS Installation

SendBeam is distributed as a Universal Mach-O binary bundle (`arm64` Apple Silicon + `x86_64` Intel) in both DMG and ZIP formats.

### A. Desktop Application

1. Download `SendBeam-macos-universal.dmg`.
2. Double-click to mount the disk image.
3. Drag **SendBeam.app** into your **Applications** folder.
4. Launch SendBeam from Applications.

> [!NOTE]
> **macOS Gatekeeper First Launch ($0 Budget / Unsigned Notice):**
> SendBeam is free open-source software built on a $0 budget without paid Apple Developer ID certificates ($99/yr). On first launch, macOS Gatekeeper may display a prompt stating the developer cannot be verified.
>
> To launch safely after verifying checksums:
>
> 1. Right-click (or Control-click) **SendBeam.app** in Applications.
> 2. Select **Open** from the context menu.
> 3. Click **Open** in the confirmation dialog.
>
> Alternatively, remove the quarantine attribute via terminal:
>
> ```bash
> xattr -d com.apple.quarantine /Applications/SendBeam.app
> ```

---

### B. CLI Terminal Client

```bash
# Extract the appropriate architecture archive (arm64 for Apple Silicon, amd64 for Intel)
tar -xzf sendbeam-cli-darwin-arm64.tar.gz

# Install to /usr/local/bin
sudo install -m 755 sendbeam /usr/local/bin/sendbeam

# Verify installation
sendbeam version
```

---

## 4. Windows Installation

SendBeam provides an NSIS executable installer, a standalone portable ZIP, and a CLI executable for Windows.

### A. Desktop Application

#### Option 1: Executable Installer (Recommended)

1. Download and run `SendBeam-windows-amd64-installer.exe`.
2. Follow the setup wizard. The installer creates Start Menu shortcuts and registers SendBeam with the Windows Uninstaller.

#### Option 2: Portable ZIP

1. Download and extract `SendBeam-windows-amd64-portable.zip`.
2. Run `sendbeam-desktop.exe` directly from the extracted folder.

> [!NOTE]
> **Windows SmartScreen Prompt ($0 Budget / Unsigned Notice):**
> SendBeam does not use commercial Microsoft Authenticode certificates ($300+/yr). Windows Defender SmartScreen may display an unknown publisher dialog ("Windows protected your PC").
>
> To proceed after verifying checksums:
>
> 1. Click **More info**.
> 2. Click **Run anyway**.

---

### B. CLI Terminal Client

1. Download and extract `sendbeam-cli-windows-amd64.zip`.
2. Copy `sendbeam.exe` to a folder included in your system `PATH` (e.g. `C:\Program Files\SendBeam` or `%USERPROFILE%\bin`).
3. Open PowerShell or Command Prompt and verify:

```powershell
sendbeam version
```

---

## 5. Cryptographic Checksum & Signature Verification

All release packages and archives are cryptographically signed and hashed in `SHA256SUMS.txt`:

### Option 1: Minisign (Ed25519) Verification

```bash
# Verify SHA256SUMS.txt against the official SendBeam public key:
minisign -Vm SHA256SUMS.txt -P RWTcyDWHWbxnuo3LVM5mWoZrx0HDwSQzAZvXK1lPRcdtJxshUDxJh+rE
```

### Option 2: Sigstore Cosign (Keyless OIDC) Verification

```bash
# Verify the GitHub Actions OIDC build identity attestation:
cosign verify-blob \
  --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity-regexp 'github.com/Akshay7273/sendbeam' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

### Option 3: SHA-256 Checksum Validation

```bash
# Verify your downloaded release file matches the signed manifest:
sha256sum -c SHA256SUMS.txt --ignore-missing
```

For full supply chain details and SBOM verification, refer to [docs/supply-chain.md](supply-chain.md).

---

## 6. Quickstart: Your First Transfer

### Web App

Navigate to [omnitrix.space](https://omnitrix.space), drop your files to generate an invite code, or enter an invite code to receive.

### CLI

```bash
# Send a file or folder:
sendbeam send ./photo.jpg

# Receive using an invite code:
sendbeam receive 7-guitarist-melody
```

### Desktop

Open **SendBeam Desktop**, click **Send Files** (or drag and drop into the window), and share the generated code or QR code with the receiver.
