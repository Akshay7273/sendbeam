# Distribution and Native Packaging

This document outlines SendBeam's distribution architecture, multi-platform artifact packaging, build metadata injection, and verification standards.

## Supported Distribution Artifacts

SendBeam produces deterministic standalone artifacts for the CLI and Desktop clients across Linux, macOS, and Windows.

### 1. CLI Distributions

The `sendbeam` terminal client is compiled as a static or minimal-dependency binary for each target OS and architecture:

| Target  | Architecture | Archive Name                       | Binary Name    |
| :------ | :----------- | :--------------------------------- | :------------- |
| Linux   | `amd64`      | `sendbeam-cli-linux-amd64.tar.gz`  | `sendbeam`     |
| Linux   | `arm64`      | `sendbeam-cli-linux-arm64.tar.gz`  | `sendbeam`     |
| macOS   | `amd64`      | `sendbeam-cli-darwin-amd64.tar.gz` | `sendbeam`     |
| macOS   | `arm64`      | `sendbeam-cli-darwin-arm64.tar.gz` | `sendbeam`     |
| Windows | `amd64`      | `sendbeam-cli-windows-amd64.zip`   | `sendbeam.exe` |
| Windows | `arm64`      | `sendbeam-cli-windows-arm64.zip`   | `sendbeam.exe` |

Each CLI archive contains:

- `sendbeam` (or `sendbeam.exe`) executable
- `LICENSE`
- `README.md`

### 2. Desktop Distributions

The SendBeam Desktop application packages the Go transfer engine with native platform presentation:

| Platform              | Format         | Development Artifact Name                             | Tagged Release Artifact Name           | Description                                                   |
| :-------------------- | :------------- | :---------------------------------------------------- | :------------------------------------- | :------------------------------------------------------------ |
| **Windows** (amd64)   | Portable ZIP   | `SendBeam-windows-amd64-portable.zip`                 | `SendBeam-windows-amd64-portable.zip`  | Self-contained executable archive with license and metadata   |
| **Windows** (amd64)   | NSIS Installer | `SendBeam-windows-amd64-installer.exe`                | `SendBeam-windows-amd64-installer.exe` | Windows installer with Start Menu shortcuts and uninstaller   |
| **macOS** (Universal) | App Archive    | `SendBeam-macos-universal.zip`                        | `SendBeam-macos-universal.zip`         | Mach-O Universal bundle (`arm64` + `amd64`) in `SendBeam.app` |
| **macOS** (Universal) | DMG Image      | `SendBeam-macos-universal.dmg`                        | `SendBeam-macos-universal.dmg`         | Disk image with drag-and-drop Applications shortcut           |
| **Linux** (amd64)     | Debian Package | `sendbeam-desktop_0.0.0~dev+git.<shortsha>_amd64.deb` | `sendbeam-desktop_<ver>_amd64.deb`     | Debian/Ubuntu `.deb` with `.desktop` menu entry and icons     |
| **Linux** (amd64)     | AppImage       | `SendBeam-linux-amd64.AppImage`                       | `SendBeam-linux-amd64.AppImage`        | Portable Linux executable with embedded runtime               |

> [!NOTE]
> Pull request and branch builds generate unsigned validation packages stored as GitHub Actions workflow artifacts (retained for 14 days in `.github/workflows/distribution.yml`). Pushing a release tag (`vX.Y.Z` or `vX.Y.Z-rcN`) triggers `.github/workflows/release.yml`, which compiles all native distributions, generates canonical `SHA256SUMS.txt`, creates in-toto provenance & SPDX 2.3 SBOM attestations, and stages a **Draft GitHub Release** for maintainer review and publication.

---

## Authoritative Version Resolution Policy

Build and packaging metadata is resolved deterministically through [scripts/version-metadata.sh](scripts/version-metadata.sh) across all CLI and desktop platforms:

| Version Field                | Untagged / Development / PR Builds | Tagged Release Builds (`vX.Y.Z`) | Prerelease Builds (`vX.Y.Z-rcN`) | Description                                                          |
| :--------------------------- | :--------------------------------- | :------------------------------- | :------------------------------- | :------------------------------------------------------------------- |
| **Internal Product Version** | `dev`                              | `X.Y.Z`                          | `X.Y.Z-rcN`                      | Go `-ldflags` embedded product build version (`ProductVersion`)      |
| **Display Version**          | `dev`                              | `X.Y.Z`                          | `X.Y.Z-rcN`                      | Human-facing CLI version UX and installer display string             |
| **macOS Short Version**      | `0.0.0`                            | `X.Y.Z`                          | `X.Y.Z`                          | `CFBundleShortVersionString` (strictly numeric `[0-9]+(\.[0-9]+)*`)  |
| **macOS Bundle Version**     | `0.0.0`                            | `X.Y.Z`                          | `X.Y.Z`                          | `CFBundleVersion` (strictly numeric dotted version)                  |
| **Windows Fixed Version**    | `0.0.0.0`                          | `X.Y.Z.0`                        | `X.Y.Z.0`                        | 4-part numeric PE `FixedFileInfo` (`FileVersion` / `ProductVersion`) |
| **Debian Package Version**   | `0.0.0~dev+git.<shortsha>`         | `X.Y.Z`                          | `X.Y.Z~rcN`                      | Debian-compliant package version string                              |
| **Git Commit**               | Exact 40-character commit SHA      | Exact 40-character commit SHA    | Exact 40-character commit SHA    | Full git commit SHA embedded via `-ldflags`                          |

Wire protocol versioning remains immutable (`sendbeam/1` and `sendbeam/2`) and is decoupled from product release versions.

### CLI Version UX

```bash
# Development build:
sendbeam version
# Output: sendbeam dev (1e937f5e07ea)

# Tagged release build:
sendbeam version
# Output: sendbeam 1.6.0 (1e937f5e07ea)

# Prerelease build:
sendbeam version
# Output: sendbeam 1.6.0-rc1 (1e937f5e07ea)
```

---

## Packaging Workflow and GitHub Releases

Packaging is automated across native GitHub-hosted runners in two dedicated workflows:

1. **Validation & PR Packaging (`.github/workflows/distribution.yml`):**
   - Runs on PRs touching client code and packaging files.
   - Compiles all matrix platforms and attaches 14-day test artifacts for CI smoke testing.
2. **Formal Release Packaging (`.github/workflows/release.yml`):**
   - Triggered on push of version tags (`v*`) or manual `workflow_dispatch`.
   - Compiles all 6 CLI platforms and all 4 desktop formats.
   - Generates canonical `SHA256SUMS.txt`, in-toto build provenance attestations, and SPDX 2.3 SBOMs.
   - Creates a **Draft GitHub Release** with all assets and checksums attached. Prerelease tags (`v*-rc*`) are marked as pre-releases.
   - Runs a **Release Verification Gate** job that downloads the release bundle, re-checks SHA-256 sums, smoke tests the native binary, and validates draft status.
   - Maintainer reviews the draft release notes and publishes the release.

### Checksum Manifest & Supply Chain Integrity

All produced distribution archives, installers, and SPDX 2.3 SBOM manifests are hashed with SHA-256 and collected into a canonical manifest:

```text
SHA256SUMS.txt
```

- Cryptographic build provenance: attested in CI via `actions/attest-build-provenance@v2`.
- Software Bill of Materials: generated via `scripts/generate-sbom.sh` (`sendbeam-cli.spdx.json`, `sendbeam-desktop.spdx.json`).
- Detailed supply chain security model: [docs/supply-chain.md](supply-chain.md).
- Standalone self-updater architecture & rollback: [docs/updater.md](updater.md).
