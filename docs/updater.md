# Updates

SendBeam has **no in-app updater**. There is no background update check, no
update channel, no downloaded manifest, and nothing replaced inside an
installed application. Updates are ordinary downloads from GitHub Releases.

---

## 1. Why there is no updater

An in-app updater has to answer one question unattended: _is this binary
authentic?_ Answering it automatically requires a long-lived signing key that
stays trusted for years on every installed machine, and the whole key-custody,
rotation and revocation apparatus that implies.

This project is free and fully open source, and distributes through GitHub
Releases. When the user downloads and installs a release themselves, the
question changes from "is this binary authentic?" to "is this the release the
project published?" — which GitHub's build-provenance attestations answer
without any key this project has to hold. Removing the updater removed the
key-management requirement at the root rather than solving it.

Historical implementation and threat-matrix documentation remains in git
history and in the release records for the versions that shipped an updater.

---

## 2. How updates work now

1. Open [GitHub Releases](https://github.com/Akshay7273/sendbeam/releases).
2. Download the artifact for your platform.
3. Optionally verify it (section 3) and install it the same way you installed
   the previous version.

Nothing polls for updates. A running installation never contacts the network
on its own to ask about a newer version.

### Existing installations that shipped an automatic updater

Clients released before the updater was removed still contain update code.
They cannot be migrated automatically — every channel they trust is
authenticated by the retired key. See
[MIGRATION-existing-clients.md](MIGRATION-existing-clients.md) for the
supported manual path, which uses Sigstore provenance rather than the retired
key.

The legacy update endpoints are permanently unavailable. No artifact is
published to them, and a guard in CI (`scripts/guard-signing-material.sh`,
rule 6) fails the build if a tracked `updates/` directory or channel manifest
reappears in the repository — which is what would make those routes resolvable
again if GitHub Pages were re-enabled.

---

## 3. Verifying a download

Every release artifact is covered by a GitHub build-provenance attestation
bound to this repository's release workflow identity:

```bash
gh attestation verify SendBeam-linux-amd64.AppImage --repo Akshay7273/sendbeam
```

Checksums are published alongside each release:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

The checksum manifest is additionally signed keyless with Sigstore, so its
provenance does not depend on any key this project holds. See
[supply-chain.md](supply-chain.md) for the full verification model and
[install.md](install.md) for per-platform install instructions.

---

## 4. What was removed, and why it is not coming back by accident

Removed in full: the framework-independent updater engine, the `sendbeam
update` CLI command, the desktop `UpdateService` and its Wails bindings, the
desktop update UI, the `updateChannel` and `autoCheckUpdate` configuration
fields, the channel-manifest generator, the Minisign signer and public key, and
the release-pipeline signing steps that depended on them.

Two guarantees keep it that way:

- `TestConfigHasNoUpdaterFields` fails if an updater field returns to the
  desktop configuration struct.
- `scripts/guard-signing-material.sh` fails CI if retired signing material or a
  legacy update route reappears in tracked files.

Reintroducing an updater is a design decision that would restore the original
key-management problem. It should be made deliberately, not by drift.
