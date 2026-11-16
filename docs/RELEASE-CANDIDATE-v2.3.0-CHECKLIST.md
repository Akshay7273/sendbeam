# v2.3.0 Release Candidate — Manual Acceptance Checklist

**Source commit:** `4a48ca10393a2e58f2968836beb5a3c13c52e38c` (main)
**Build:** `distribution.yml` run `43793371457` (workflow_dispatch, 13/13 jobs success)
**Status of candidate:** built, checksummed, attested, structurally inspected, Linux launch smoke-tested on this exact SHA.
**Status of release:** **NOT RELEASED.** No tag exists. No GitHub Release exists. Publication requires every row below plus owner approval.

> **Why the binaries say `dev`, not `2.3.0`:** `scripts/version-metadata.sh`
> stamps only tag builds with a version number; an untagged build is
> intentionally `dev` + `0.0.0~dev+git.<sha>`. Producing `2.3.0`-labelled
> artifacts would require the release tag, which does not exist yet. The
> candidate is therefore identified by **source SHA**, exactly as the SB-R10
> run was. Every binary embeds `vcs.revision=4a48ca10393a2e58f2968836beb5a3c13c52e38c`,
> `vcs.modified=false`.

---

## 1. Where to download the candidate

GitHub Actions artifact (expires **2026-11-30**, 14-day retention):

<https://github.com/Akshay7273/sendbeam/actions/runs/43793371457>

Download the single artifact **`sendbeam-distribution-4a48ca10393a2e58f2968836beb5a3c13c52e38c`**
(89.6 MB) — it contains all 14 files below. Command line:

```bash
gh run download 43793371457 \
  --repo Akshay7273/sendbeam \
  -n sendbeam-distribution-4a48ca10393a2e58f2968836beb5a3c13c52e38c \
  -D sendbeam-rc-v230
```

### Files in the bundle (SHA-256 published below)

| File                                                    | Platform / purpose            |
| ------------------------------------------------------- | ----------------------------- |
| `SendBeam-windows-amd64-installer.exe`                  | Windows installer (NSIS)      |
| `SendBeam-windows-amd64-portable.zip`                   | Windows portable              |
| `SendBeam-macos-universal.dmg`                          | macOS universal disk image    |
| `SendBeam-macos-universal.zip`                          | macOS universal app zip       |
| `SendBeam-linux-amd64.AppImage`                         | Linux desktop (AppImage)      |
| `sendbeam-desktop_0.0.0~dev+git.4a48ca10393a_amd64.deb` | Linux desktop (Debian)        |
| `sendbeam-cli-linux-amd64.tar.gz`                       | CLI linux/amd64               |
| `sendbeam-cli-linux-arm64.tar.gz`                       | CLI linux/arm64               |
| `sendbeam-cli-darwin-amd64.tar.gz`                      | CLI macOS Intel               |
| `sendbeam-cli-darwin-arm64.tar.gz`                      | CLI macOS Apple Silicon       |
| `sendbeam-cli-windows-amd64.zip`                        | CLI windows/amd64             |
| `sendbeam-cli-windows-arm64.zip`                        | CLI windows/arm64             |
| `sendbeam-cli.spdx.json`                                | CLI SPDX SBOM                 |
| `sendbeam-desktop.spdx.json`                            | Desktop SPDX SBOM             |
| `SHA256SUMS.txt`                                        | Checksums of all of the above |

### SHA-256 of the candidate (record these in your evidence)

```
1603c9682668114d5a34b96bd6008938f522b5095454d1a320440280df8dc3af  SendBeam-linux-amd64.AppImage
900e16f13e194e4c8ca436bad600f04846c0e9d6a9af315222a060d079546de2  SendBeam-macos-universal.dmg
a8a7df96a7f7cf6e4ea3b8a5ad6b21ceb99556b4eae5a6d789b5853c211662b4  SendBeam-macos-universal.zip
26c3a8fd735245c93cf5ba20d5b1dbc1f393c654fa2ba3d7cc2f1fdbb9e6ef95  SendBeam-windows-amd64-installer.exe
2f45a2f9799854c2c49f595501c1b49ba7e771d35f054f57c0f905e7a5e79116  SendBeam-windows-amd64-portable.zip
185bc98cb8d330800154fe8ea70ad6bd9763a3ee2016c74a21bd802a34327dee  sendbeam-cli-darwin-amd64.tar.gz
682dc3e78c9481180946859f6d50413f8ed631ff4c8473bf715c5618581dda51  sendbeam-cli-darwin-arm64.tar.gz
1fb9cd0f6d2c9e8022e3637abbecc5cf62e23b120bfe89f7a6ddc6f206b71c1a  sendbeam-cli-linux-amd64.tar.gz
7175ed4a02364dc1430fa5cc67a2c3791c7b5bd149e970b71ce0f9947c12db7e  sendbeam-cli-linux-arm64.tar.gz
b1ac7c97caee406496cf30cae7b0a8cd493d2de7de5d0a81daef100d9d53cbd6  sendbeam-cli-windows-amd64.zip
c717b63686bac8f5b13db1aefb1240fde9530aad4308285dd0c102c9a108231c  sendbeam-cli-windows-arm64.zip
3e25b13e8b5d7a3809a7830d230197b84899d4afd39cb6351ccf9a2c78503151  sendbeam-cli.spdx.json
6bd88a390aa6fddc60b20298d44eb6028e3b79ddd165d34c72c864650f276240  sendbeam-desktop.spdx.json
9eb60b8e7a39497ec6ad47388e4889394ee4d826d874450b3752a2fea8faf463  sendbeam-desktop_0.0.0~dev+git.4a48ca10393a_amd64.deb
```

### Verify before installing (30 seconds, any OS)

```bash
sha256sum -c SHA256SUMS.txt        # Linux
shasum -a 256 -c SHA256SUMS.txt    # macOS
# Windows (PowerShell): Get-FileHash <file> -Algorithm SHA256
```

Provenance (optional but recommended, needs `gh`):

```bash
gh attestation verify SendBeam-linux-amd64.AppImage --repo Akshay7273/sendbeam
```

Expected identity: `.github/workflows/distribution.yml@refs/heads/main`,
predicate `https://slsa.dev/provenance/v1`.

---

## 2. Already proven — DO NOT re-run

Only the essentials are below; these are done and recorded:

| Evidence                                                                                                     | Where                            |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------- |
| 14/14 SHA-256 checksums verified from a fresh download                                                       | this document, run `43793371457` |
| Build provenance + SBOM attestations verified via `gh attestation verify`                                    | this document                    |
| Embedded `vcs.revision=4a48ca1…`, `vcs.modified=false` in all 6 CLI + all desktop binaries                   | this document                    |
| Structural inspection: macOS `.app` zip, DMG `koly` trailer, deb contents, NSIS PE, Windows portable payload | this document                    |
| Linux AppImage launch under Xvfb (Wails window, GTK 4.14.5 / WebKitGTK 2.52.6, all stores created)           | this document                    |
| Linux CLI smoke (`sendbeam version`, `--help`, `transfers list`)                                             | distribution run `smoke` job     |
| Engine/desktop suites, race, fuzz smoke, offline lab, differential                                           | CI on `4a48ca1` — all green      |

---

## 3. What YOU must run personally

Seven rows. Nothing here can be executed by an agent: each needs a real OS
install, a real window, or a second physical machine.

### Row A — Windows install & launch (needs a Windows 10/11 host)

1. Verify `SendBeam-windows-amd64-installer.exe` against `SHA256SUMS.txt`.
2. Run the installer (it requests administrator). Complete it.
3. Launch **SendBeam** from the Start menu.
4. Confirm: window opens, no error dialog, app shows its main view.
5. Open **Recipes** → create a recipe pointing at a local folder → save.
6. Close the app, reopen it, confirm the recipe is still listed.
7. Uninstall via Settings → Apps, confirm removal and that
   `%APPDATA%\sendbeam` recipe data survives on disk (expected: data preserved).

Record: `A` PASS/FAIL.

### Row B — macOS install & launch (needs a macOS host, Intel or Apple Silicon)

1. Verify `SendBeam-macos-universal.dmg` against `SHA256SUMS.txt`.
2. Open the DMG, drag **SendBeam.app** to Applications.
3. First launch: Gatekeeper will warn (the build is unsigned/not notarized —
   expected, and a known pre-1.0 gap). Use right-click → **Open**, or
   System Settings → Privacy & Security → **Open Anyway**.
4. Confirm: window opens, no crash, main view renders.
5. Create + save a recipe in a local folder; quit and relaunch; recipe persists.
6. Delete the app from Applications; confirm `~/Library/Application Support/sendbeam`
   data remains.

Record: `B` PASS/FAIL. Note the Gatekeeper wording you saw — it is expected
evidence, not a failure.

### Row C — Linux install & launch (needs a real desktop session with a WM)

Already launched headless under Xvfb at this SHA; this row is the **interactive**
part that Xvfb could not provide.

1. Verify `SendBeam-linux-amd64.AppImage` (or the `.deb`) against `SHA256SUMS.txt`.
   AppImage needs FUSE (`sudo apt install libfuse2`) — or run `--appimage-extract`.
2. Launch the app from your desktop session.
3. In the real window: **create → preview → approve → run** a recipe to a local
   folder. Confirm the delivered file appears with correct content.
4. Confirm **Cancel** on a running job returns the job to a stopped state with
   no delivered file and no "verified" badge.
5. Confirm the watch/schedule start-stop controls actually start and stop the
   runtime.
6. Change a recipe's scope/source and confirm the re-approval prompt appears.
7. Uninstall (remove AppImage / `apt remove sendbeam-desktop`) and confirm
   `~/.config/sendbeam` data survives or is removed per your expectation.

Record: `C` PASS/FAIL per sub-item (C1 delivery, C2 cancel, C3 watch/schedule,
C4 re-approval, C5 uninstall).

### Row D — Two-device LAN transfer (needs TWO real machines on one LAN)

1. Install SendBeam on machine 1 and machine 2 (any two of Windows/macOS/Linux).
2. On both, open SendBeam and pair the devices (use the pairing flow shown in
   the app; record the 6-digit/short code path you used).
3. On machine 1, create a recipe targeting machine 2, source = a file of at
   least 50 MB.
4. Run it. Confirm on machine 2 that the file arrives at the chosen destination
   with **byte-identical** content (`sha256sum` on both sides).
5. Confirm the sender shows a **verified** delivery status with a digest.
6. **Cancel test:** start a larger transfer and cancel mid-stream. Confirm the
   receiver has NO final file, the sender shows cancelled (not verified), and
   re-running the same recipe resumes and completes correctly.

Record: `D` PASS/FAIL, and paste both sides' hashes.

### Row E — NAT / relay route (needs two machines on DIFFERENT networks)

1. Same as Row D, but machine 1 and machine 2 are on different networks
   (e.g. one on mobile hotspot, one on home Wi-Fi) so a direct LAN path is
   impossible.
2. Pair, send a ≥ 20 MB file, verify byte equality on the receiving side.

Record: `E` PASS/FAIL or BLOCKED with the reason (e.g. no relay available).
If the app cannot establish any route, record that verbatim — it is important
evidence.

### Row F — Cross-version compatibility (needs the published v2.2.0 build + candidate)

1. Install published **v2.2.0** on machine 1 (<https://github.com/Akshay7273/sendbeam/releases/tag/v2.2.0>).
2. Install this **candidate** on machine 2.
3. Pair and send a file; verify byte equality both ways if possible.

Record: `F` PASS/FAIL.

### Row G — Mobile browsers (needs a real Android phone and/or iPhone)

Native mobile apps **do not exist and are out of scope** (deferred by design).
Only the browser/PWA path is in scope.

1. On the phone browser, open the SendBeam web app served by a desktop peer
   (same URL/QR the app shows for browser access).
2. Confirm the page loads and renders on the phone screen.
3. If the flow is offered: receive or send one small file and confirm it
   completes.

Record: `G` PASS/FAIL per platform (Android Chrome, iOS Safari). If the product
does not expose a browser peer flow at all, record **NOT APPLICABLE** with that
observation — do not record PASS.

---

## 4. How to record results (existing recorder — no new tooling)

Use `scripts/acceptance-record.sh` from the repo at this commit. It refuses to
accept a PASS row without full provenance, so fabricated or half-filled rows
cannot be rendered as passing.

```bash
cd ~/projects/sendbeam   # at 4a48ca1
E=~/sendbeam-v230-acceptance.jsonl

# A PASS row requires: os arch artifact-sha exe-version source-sha operator timestamp evidence
bash scripts/acceptance-record.sh record "$E" A PASS \
  os=windows arch=amd64 \
  artifact-sha=26c3a8fd735245c93cf5ba20d5b1dbc1f393c654fa2ba3d7cc2f1fdbb9e6ef95 \
  exe-version="$(cat exe-version.txt)" \
  source-sha=4a48ca10393a2e58f2968836beb5a3c13c52e38c \
  operator=akshay timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  evidence="Windows install+launch+recipe persist; screenshot win-rowA.png" \
  digest=sha256 mode=local network=lan

# A row you could not run:
bash scripts/acceptance-record.sh record "$E" E BLOCKED reason="no relay path available"

# Validate and render the report
bash scripts/acceptance-record.sh validate "$E"
bash scripts/acceptance-record.sh report   "$E"
```

Notes:

- `exe-version` = the installed app's version string (desktop window/about, or
  `sendbeam version` for CLI). For this candidate expect `dev (4a48ca10393a)`.
- `evidence` = a short factual description plus the filename of at least one
  screenshot or log you keep. The recorder stores the reference, not the file.
- Add `--` free-form keys only from the supported set; unknown keys are rejected
  by design.

### What to send back to me

1. The JSONL file (or its `report` output) with rows A–G filled honestly.
2. For any PASS: one screenshot or log per row, named `win-rowA.png`,
   `mac-rowB.png`, `linux-rowC1.png`, `lan-rowD.png`, etc.
3. For Row D/E/F: the two SHA-256 hashes from both sides.
4. Any deviation, crash, or warning text you saw — verbatim.

---

## 5. What happens after your results

- **All rows PASS** → I prepare the tag/release step for your explicit
  approval; `release.yml` rebuilds from the tag, regenerates manifests from the
  real `SHA256SUMS.txt`, and opens the manifest-sync PR afterwards.
- **Any row FAIL** → I fix exactly that defect, we rebuild a candidate from the
  new SHA, and only the failed row plus its neighbours are re-run.
- **BLOCKED rows** → recorded as BLOCKED; a blocked row is a publication
  blocker, not a pass.

No tag, no release, and no publication happens without your explicit go-ahead.
