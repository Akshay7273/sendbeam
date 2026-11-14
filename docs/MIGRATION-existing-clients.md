# Existing-Client Migration

Status: **prepared, NOT published.** Owner approval required before this
material is used in an advisory or release announcement.

Audience: users running SendBeam **v1.6.0 – v2.2.x** (every updater-capable
release) whose shipped trust anchor is the retired key.

> **Updated 2026-11-15 (SB-SIMPLIFY).** The originally planned key rotation was
> replaced by removal: the automatic updater and its signing key no longer
> exist in any current build, so there is no replacement trust anchor for old
> clients to migrate _to_. That does not change any instruction in this
> document — every step here was already a manual, out-of-band download — but
> it does change the destination: migrate to a current release, which has no
> updater at all, rather than to a re-pinned one.

Related: [`SECURITY-INCIDENT-SB-SEC01.md`](SECURITY-INCIDENT-SB-SEC01.md),
[`updater.md`](updater.md).

---

## 1. The core constraint

A client pinned to the retired key **cannot be securely told to trust a new
key by an automatic update**. Any update channel the old client consults is
authenticated by the very key that must be withdrawn, so an automatic
migration is by construction forgeable. Therefore:

- There is **no** automatic upgrade path from v1.6–v2.2, and none will be
  offered. Current builds contain no updater and no update channel, so there is
  nothing for an old client to be migrated onto automatically.
- There is **no** compatibility mode in which retired-key signatures remain
  sufficient for anything. The signer and verifier that would accept them no
  longer exist in the project.
- Migration is a **manual, out-of-band download** over an independently
  authenticated channel.

The practical consequence is reassuring: the production update endpoint has
never been provisioned (see SEC01 §8), so no vulnerable client can currently
be pushed an update at all. Migration is a user action, not an emergency.

---

## 2. What counts as independent authentication

The retired key signed `SHA256SUMS.txt` and the channel manifests for every
release up to and including v2.2.0 — and, on 2026-09-29, those files were
**re-signed with the retired key** during the asset-scrub operation. So:

> **A checksum file whose only authentication is a minisign signature from
> the retired key is NOT independent authentication.** It can be forged by
> anyone who has read this repository.

The acceptable independent anchor is **Sigstore keyless provenance**: a
Fulcio certificate bound to the GitHub Actions OIDC identity of this
repository's release workflow, recorded in the public Rekor transparency log.
That identity cannot be produced outside GitHub Actions for this repository,
and the retired key plays no part in it.

```bash
gh attestation verify <artifact> --repo Akshay7273/sendbeam
```

A successful verification binds the artifact bytes to:

- workflow: `.github/workflows/release.yml`
- ref: `refs/tags/v2.2.0`
- source commit: `87d2628fa60f8c55ed174c1a119d86824444df05`
- issuer: `https://token.actions.githubusercontent.com`
- Rekor log timestamp

---

## 3. Verified provenance status of the current v2.2.0 assets

Measured on 2026-11-14 by downloading each published asset and running
`gh attestation verify` against repository `Akshay7273/sendbeam`.

| Asset                                             | Independent provenance                |
| ------------------------------------------------- | ------------------------------------- |
| `SendBeam-linux-amd64.AppImage`                   | **VERIFIED**                          |
| `SendBeam-macos-universal.dmg`                    | **VERIFIED**                          |
| `SendBeam-windows-amd64-installer.exe`            | **VERIFIED**                          |
| `SendBeam-macos-universal.zip`                    | stale — no longer matches attestation |
| `SendBeam-windows-amd64-portable.zip`             | stale — no longer matches attestation |
| `sendbeam-desktop_2.2.0_amd64.deb`                | stale — no longer matches attestation |
| `sendbeam-cli-linux-amd64.tar.gz`                 | stale — no longer matches attestation |
| `sendbeam-cli-linux-arm64.tar.gz`                 | stale — no longer matches attestation |
| `sendbeam-cli-darwin-amd64.tar.gz`                | stale — no longer matches attestation |
| `sendbeam-cli-darwin-arm64.tar.gz`                | stale — no longer matches attestation |
| `sendbeam-cli-windows-amd64.zip`                  | stale — no longer matches attestation |
| `sendbeam-cli-windows-arm64.zip`                  | stale — no longer matches attestation |
| `SHA256SUMS.txt` (+ `.minisig`, `.sigstore.json`) | stale — re-signed in the scrub        |

"Stale" means: the attestation bundle exists and is internally valid, but the
**bytes currently published no longer match the attested digests**. This is
the direct consequence of the 2026-09-29 scrub re-upload, which replaced
artifacts without re-attesting them. It is a provenance gap, not evidence of
tampering — but it means those files cannot be authenticated by provenance
today, and users must not be told otherwise.

Three installed-format artifacts (AppImage, DMG, Windows installer) retain
valid provenance. Recommended migration therefore routes through those.

---

## 4. Per-platform migration

Every command below is copy-pasteable. Substitute the release directory and
the version once the replacement release exists.

### 4.1 Common verification step (all platforms)

```bash
# 1. Fetch the artifact and the attestation-verification tool output.
gh release download <TAG> --repo Akshay7273/sendbeam --pattern '<artifact>'

# 2. Verify provenance — this is the independent anchor.
gh attestation verify '<artifact>' --repo Akshay7273/sendbeam
# Expect: "Loaded ... attestations" and a Verified OK result naming
# .github/workflows/release.yml and refs/tags/<TAG>.
```

Do **not** rely on `minisign -Vm SHA256SUMS.txt -P <retired fingerprint>` for
this migration, and do not rely on a Minisign signature at all. The retired key
is compromised, so any signature it produced proves nothing about who published
those bytes. Current releases are not Minisign-signed — the signer and its
public key were removed with the updater — so use the build-provenance
attestation above.

### 4.2 Windows — installer (recommended) and portable

**Installer path (has valid provenance today):**

1. Download `SendBeam-windows-amd64-installer.exe` for the replacement
   release.
2. Verify provenance as in §4.1 from PowerShell:
   ```powershell
   gh attestation verify .\SendBeam-windows-amd64-installer.exe --repo Akshay7273/sendbeam
   ```
3. Record the SHA-256: `Get-FileHash .\SendBeam-windows-amd64-installer.exe -Algorithm SHA256`
4. Run the installer. It replaces the existing installation in place.
5. Launch SendBeam and confirm the version in the About panel.
6. Confirm the old client no longer exists: the installer upgrades the same
   install directory rather than adding a second copy.

**Portable path (provenance currently stale):** the published portable ZIP
does not match its attestation after the scrub. Either wait for a
replacement-release portable build (which will be attested), or use the
installer. Do not skip provenance verification for the portable ZIP.

### 4.3 macOS — DMG

1. Download `SendBeam-macos-universal.dmg`.
2. Verify provenance:
   ```bash
   gh attestation verify SendBeam-macos-universal.dmg --repo Akshay7273/sendbeam
   ```
3. Verify the recorded digest against the published value from a **second**
   channel (release page + `SECURITY.md` fingerprint listing).
4. Open the DMG, drag **SendBeam.app** to `/Applications`, replacing the
   existing copy when prompted.
5. Because the app is ad-hoc/Developer-ID signed as before, macOS may require
   a right-click → **Open** on first launch.
6. Confirm the version in the About panel.

### 4.4 Linux — AppImage (recommended) and deb

**AppImage (has valid provenance today):**

```bash
gh release download <TAG> --repo Akshay7273/sendbeam --pattern 'SendBeam-linux-amd64.AppImage'
gh attestation verify SendBeam-linux-amd64.AppImage --repo Akshay7273/sendbeam
chmod +x SendBeam-linux-amd64.AppImage
./SendBeam-linux-amd64.AppImage   # replaces the previous AppImage in place
```

If the existing installation lives elsewhere, move the verified AppImage over
the old file yourself; the client does not manage its own location.

**deb (provenance currently stale for the published v2.2.0 build):**

```bash
sudo apt remove sendbeam-desktop    # or: sudo dpkg -r sendbeam-desktop
sudo apt install ./sendbeam-desktop_<VERSION>_amd64.deb
```

`apt`-installed copies are **not** self-updated by the updater (it refuses and
defers to the package manager), so for deb users the risk window is limited
to the package source. Migrate by pointing at the repository that ships the
replacement release once it exists.

### 4.5 CLI

```bash
# Linux/macOS
gh release download <TAG> --repo Akshay7273/sendbeam --pattern 'sendbeam-cli-<os>-<arch>.tar.gz'
gh attestation verify sendbeam-cli-<os>-<arch>.tar.gz --repo Akshay7273/sendbeam
tar -xzf sendbeam-cli-<os>-<arch>.tar.gz
sudo install -m 0755 sendbeam /usr/local/bin/sendbeam
sendbeam --version
```

For the currently published v2.2.0 CLI archives, provenance is stale (§3).
Prefer the replacement release, whose archives will be attested. Package
managers (Homebrew/Scoop/WinGet/AUR) are outside the updater's trust path and
migrate through their own index updates.

---

## 5. Classification for the advisory

| Group                                   | Definition                                                          | Advice                                                                                                 |
| --------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **New installs**                        | installing the replacement release for the first time               | verify provenance, then install; no legacy trust involved                                              |
| **Migrated**                            | existing v1.6–v2.2 install replaced by a verified replacement build | manual download required; confirm the version afterwards                                               |
| **Cannot migrate automatically**        | every existing install, by construction                             | must follow §4 manually                                                                                |
| **Non-recoverable without user action** | installs abandoned before migration                                 | remain pinned to the retired key; they cannot be updated securely and should be treated as end-of-life |

### Assets with valid independent provenance vs. stale attestation

- **Valid today:** linux AppImage, macOS DMG, windows installer.
- **Stale today:** every other published v2.2.0 asset, including all CLI
  archives, the portable ZIP, the deb, and `SHA256SUMS.txt` itself.

Any wording that presents `SHA256SUMS.txt` + retired-key `minisign`
verification as sufficient for the stale set would be false and must not be
published.

---

## 6. Advisory wording constraints

The published advisory must:

- state that the key material was exposed and is being replaced, **not** that
  replacement is complete;
- state that v1.6–v2.2 clients cannot self-update securely and must be
  replaced manually;
- give `gh attestation verify` as the independent check, with the exact
  workflow identity;
- name which artifacts currently have valid provenance and which do not;
- avoid implying that a retired-key minisign signature authenticates anything;
- carry the owner's approval before publication.

Draft text lives in `SECURITY-INCIDENT-SB-SEC01.md` §9 and is corrected to
these constraints.

---

## 7. What remains owner-gated

- Publishing the advisory or any announcement.
- Creating the replacement release that migration targets.
- Any change to the update endpoint.
- Deleting the retired GitHub secret.
- Issuing a CVE.

This document is preparation only; no migration has been announced.
