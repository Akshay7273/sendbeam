# SB-SEC01 — Production Update Signing-Key Compromise: Investigation Record

**Status:** CONFIRMED compromise of the production update-signing trust
anchor. Containment prepared; rotation and channel changes are OWNER-GATED
(no key generation, no signing, no publishing, no endpoint changes performed).
**Prepared:** 2026-11-14, fryday workbench, repo at `731e4f102614` (SEC01
PR-1). This record is investigation output — evidence and non-secret
fingerprints only.

---

## 1. Confirmed finding (Phase A)

The minisign test-fixture seed committed in `packages/engine/updater/updater_test.go`
and 8 other tracked test files since **#143 (b78a13e, 2026-08-27 20:39:49 +0530)**
derives the **exact pinned production update-signing public key**.

Independent re-verification (fingerprint-only probe; no secret material
printed, committed, or transmitted):

```
derived_pub_sha256_fp=e8576849c9dfd0a0…f5e818866a241a00
pinned_pub_sha256_fp=e8576849c9dfd0a0…f5e818866a241a00
public_key_bytes_identical=true
signature_verifies_under_pinned_key=true
```

Implication: any repository reader (public repo) can derive the production
signing key and produce manifests/signatures that **every shipped client
(v1.6–v2.2) accepts as authentic**. `VerifyMinisignSignature` itself is not
broken; the key it pins is exposed. The production keyID printed in
signatures (`BA67BC598735C8DC`) is reproduced trivially by the attacker
(`SignMinisign` copies the keyID from the provided public-key file); keyID
checking provides no protection.

**No exploitation evidence** (below); the exposure is confirmed by
derivation, not by observed abuse.

## 2. Affected-version and platform inventory

| Surface                                 | Scope                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Git history                             | Seed reachable at 7+ commits (all `--all` refs; earliest b78a13e). Present in every tag from **v1.6.0 (2026-08-28)** onward, in all currently-shipped source archives (v2.2.0 zip verified). NOT removable without history rewrite (forbidden).                                                                                                                |
| Compiled clients                        | Every updater-capable release embeds the exposed pin: v1.6.0 → v2.2.0 (verified in v2.2.0 tree `87d2628f`: 11 test files carry the seed; pin identical in `apps/cli/internal/updater` + `packages/engine/updater`). v1.5 and earlier have **no updater** (signed-manifest feature arrived #143).                                                               |
| Signed artifacts re-signed with the key | ALL published releases' `SHA256SUMS.txt` + `stable.json` + `beta.json` re-signed **2026-09-29** by the documented domain-scrub operation (#235–#240): minisig trusted comments `timestamp:1790708270–1790708695 … scrub:1`, cosign certs bound to `scrub-release-assets.yml@refs/heads/main`. v1.6.0–v1.8.0 same treatment (asset `updated_at` churn matches). |
| Other credentials                       | Only `secrets.MINISIGN_SECRET_KEY` (x3 uses in release.yml). No other signing keys referenced. GHCR publish path uses GITHUB_TOKEN + keyless OIDC only.                                                                                                                                                                                                        |
| CI logs                                 | No seed occurrence in workflow logs (latest run checked: 0 hits). Test stdout never prints the seed.                                                                                                                                                                                                                                                           |
| The keyID `BA67BC598735C8DC`            | appears in `minisign.pub` (committed), `verify.go` comment, `docs/supply-chain.md`, release.yml release notes template. All public by design.                                                                                                                                                                                                                  |

## 3. Incident timeline and exposure assessment

| Date (UTC)             | Event                                                                                                                                                                                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-08-27 20:39       | #143 merges: signed manifests + minisign verification. The production pin and a test seed deriving it are committed together.                                                                                                                                  |
| 2026-08-28 → 09-20     | Releases v1.6.0–v2.2.0 published; each embeds the exposed pin and ships the seed in its source archive.                                                                                                                                                        |
| 2026-09-29 18:57–19:05 | Owner-run **scrub-release-assets** (workflow_dispatch, #235–#240): all published release assets re-uploaded; checksums/manifests **re-signed with the compromised key** (trusted comments `scrub:1`). Everything still verifies because the key didn't change. |
| 2026-09-30             | Channel policy note (publish.yml): GHCR `latest` = newest green main; **production update channel (GitHub Pages) never actually existed** — see §7.                                                                                                            |
| 2026-11-14 (SB-R11)    | Finding discovered during upgrade/rollback testing (test seed → production pin derivation), reported to owner, not patched (rotation = owner decision).                                                                                                        |
| 2026-11-14 (SB-SEC01)  | Owner authorizes incident response. Phase A re-verified independently; PR-1 (#301, merged `731e4f102614`) retires the seed from test code + adds CI guard.                                                                                                     |
| Exposure window        | 2026-08-27 → present (**79+ days**), public the entire time.                                                                                                                                                                                                   |

Exploitation assessment: the seed has been public in an open repository for
79 days with the signing key held in a single GitHub Actions secret that is
**not required to be hardware-backed**. Derivation is deterministic; an
attacker never needs the secret itself. There is **no audit trail for
minisign signatures** (unlike Sigstore/Rekor), so historical manifests cannot
be proven legitimate after the fact — any party could have produced
indistinguishable signatures at any time. The honest position: treat ALL
past and present minisign signatures over release manifests as untrusted;
rely on the **keyless Sigstore provenance** (see §7) for authenticity going
back to 2026-09-20's release runs.

## 4. Immediate containment choices and impact

No containment action has been taken against live infrastructure (owner
gated). Choices, with consequences:

| Option                                                              | Effect on already-installed clients                                                                                                                            | Effect on attack                                                                                               | Owner call              |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------- |
| **Freeze releases** (no new signed artifacts under old key)         | None                                                                                                                                                           | Stops adding trust events under the compromised key                                                            | recommended immediately |
| **Rotate key + re-pin (dual-sign transition)**                      | v2.3+ clients accept new key; **v2.2- clients CANNOT verify new-key manifests and will simply not update** (fail-closed)                                       | Restores cryptographic control for new clients; old clients remain exposed to forged-update attack via old key | required (Phase C)      |
| **Disable the update endpoint** (the Pages channel)                 | **Moot: it does not exist (404 today) — clients already cannot check for updates** (see §7). Removing `DefaultUpdateBaseURL` hardcode = code change (PR-ready) | N/A today                                                                                                      | recommended             |
| **Revoke old key in clients** (re-pin to nothing = disable updates) | All clients stop updating (fail-closed); prevents forged-update attack via old pin                                                                             | Full; but destroys update path for everyone until manual upgrade                                               | alternative to rotation |
| **History rewrite / seed scrub**                                    | Forbidden per instructions; also ineffective (forks, clones, published source archives persist)                                                                | Cosmetic                                                                                                       | rejected                |

Migration/mutual-authentication notes for Phase D are in §8.

## 5. Secure replacement-key custody and provisioning plan (Phase C design)

1. **Generation (owner, offline):** `go run ./scripts/minisign.go keygen` on
   an air-gapped or trusted offline machine; **cryptographically secure
   random source**, independent of every repository constant. Record:
   keyID, public-key SHA-256 fingerprint (the ONLY value that should ever be
   shared/published). Private key never touches any online machine, repo,
   CI log, or test fixture.
2. **Custody:** private key in encrypted offline storage (2 media, 2
   locations) + GitHub Actions secret `MINISIGN_SECRET_KEY_V2` (for the CI
   signing step only). Recovery procedure: restore from offline backup,
   verify public fingerprint matches the committed pin before use.
3. **Provisioning into code:** replace
   `packages/engine/updater/verify.go::DefaultMinisignPublicKey` (and the
   CLI mirror) **only after the owner has generated + verified the
   replacement**; commit `minisign.pub` in the same commit; the SEC01 guard
   (rule 5) enforces pub↔pin consistency forever.
4. **Production-build rejection of the retired key:** after re-pin, the old
   anchor no longer exists in production binaries (the constant is the only
   trust root); guard rules 1–4 keep it out of the repo. Negative tests
   (Phase E list) prove retired-key signatures fail on new clients.
5. **Test keys:** all automated tests use independent disposable keys
   (already merged in #301; generation recipe in the guard self-tests).

## 6. Existing-client migration strategy (Phase D analysis)

**Bootstrap trust problem:** existing clients verify manifests against the
compromised key; a new-key manifest is REFUSED by them (fail-closed). An
update signed by the old key cannot securely deliver the new pin — the
attacker can produce one too. Therefore:

| Install class                                  | Path                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **New installations (post-rotation)**          | Download v2.3+ from official GitHub Releases; verify with the NEW pinned key (embedded) and the keyless Sigstore provenance bundle; minisign-verify `SHA256SUMS.txt` with published `-P` fingerprint from a second channel (SECURITY.md).                                                                                                                                               |
| **Existing installs with working users**       | **Out-of-band manual migration:** user downloads the new release/manifest root from GitHub Releases over TLS, verifies the Sigstore bundle (cosign, workflow-identity-pinned) or manually compares published fingerprints; then installs over the old version. Documented per-platform commands (draft advisory §9). No automatic path exists that doesn't rely on the compromised key. |
| **Installations that cannot verify (offline)** | Manual: fetch on another machine, transfer via physical media, verify checksums against the signed manifest + fingerprint from the security advisory.                                                                                                                                                                                                                                   |
| **Clients that will silently never update**    | v2.2- clients keep working file-transfer (pairing/transfer do not depend on the update channel — the channel is dead anyway, §7); they remain exposed to forged-update attacks only if an attacker can also get the client to fetch a manifest — currently impossible (dead endpoint), but re-enablement under the OLD pin must be treated as an attack window.                         |
| **Package-manager installs (deb)**             | Updater disabled by design; users upgrade via the repository/package — but the deb itself is signed only by the compromised key: rely on Sigstore provenance + release-page digests for the migration package.                                                                                                                                                                          |

**No compatibility mode** that continues accepting compromised-key
signatures will be introduced.

## 7. SB-R10 attestation-404 investigation — RESOLVED (evidence-based)

- The 404s recorded in SB-R10/R11 were **not** missing attestations:
  `gh attestation verify` 404s for _re-uploaded_ assets whose digests changed
  after attestation (2026-09-29 scrub re-uploads), while the web
  `github.com/<org>/<repo>/attestations/<id>` pages (and per-file `--format
json`) correctly expose the originals.
- **Actually performed** during SEC01 Phase A:
  - R10 distribution run `43573458273` bundle (14 files, digests == bundle's
    own `SHA256SUMS.txt`): **`gh attestation verify` VERIFIED** for
    SHA256SUMS.txt, linux AppImage, cli tarballs (linux/windows), the deb,
    and the NSIS installer — Sigstore bundle, cert SAN
    `.../workflows/distribution.yml@refs/pull/297/merge`, issuer
    `token.actions.githubusercontent.com`, run @ a34ded23bbd1.
  - v2.2.0 published release: original publish run `35528343494` created
    attestations (3 bundles, IDs 48783470/48783472/48783479, 17 subjects).
    **Keyless cosign verification of the CURRENT (09-29 scrub-signed)
    `SHA256SUMS.txt.sigstore.json` VERIFIED OK** with identity
    `scrub-release-assets.yml@refs/heads/main` (matches
    `scripts/verify-release.sh` F10 identity policy and docs/supply-chain.md
    §5 verbatim).
- **Platform inventory of independent provenance (v2.2.0 TODAY):** only the
  linux AppImage, macOS DMG, and windows installer carry still-valid
  build-provenance attestations (byte-identical to attested subjects). All
  other assets (CLI tarballs, deb, portable zip, macOS zip, manifests) are
  byte-different from attested subjects → **no independent provenance**;
  their only signatures are from the compromised key.
- Conclusion: Sigstore/keyless OIDC is the **only surviving authenticity
  signal** for released artifacts; it must anchor the Phase D migration.

## 8. Update-channel reality (new Phase A finding)

`DefaultUpdateBaseURL` (compiled into every updater-capable client) points to
`https://akshay7273.github.io/sendbeam/updates` — **which has never been
provisioned**: GitHub Pages API → 404 (Pages not enabled); live URL → GitHub
"Site not found". Verified against v2.2.0 (`87d2628f`) and current main:
same constant. Consequences:

- **No v1.x/v2.x client can currently receive an automatic update at all**;
  `CheckUpdate` fails with a network error (fail-closed, then surfaces an
  error to the user). The compromised-key exposure is therefore **not
  currently reachable** via the normal update path — the highest-value
  containment (keeping the endpoint disabled) is already the state.
- The signed `stable.json`/`beta.json` shipped as release assets were
  channel manifests _for_ this endpoint, but the endpoint never went live.
- Owner decisions this enables: (a) keep the endpoint dark until rotation is
  complete (recommended); (b) stand up the Pages endpoint ONLY after v2.3
  with the new pin ships; (c) remove/replace the dead URL (small code PR,
  ready on request).

## 9. Draft user-facing security advisory (OWNER APPROVAL REQUIRED — DO NOT PUBLISH)

> **[DRAFT — requires owner approval before publication]**
>
> **Advisory: SendBeam update-signing key material was publicly exposed**
>
> Summary: Between 2026-08-27 and the release of v2.3, a file in the public
> SendBeam repository contained a test signing credential that also
> functioned as the production update-signing key. We have no evidence of
> malicious use. Out of caution, we have replaced the signing key and are
> re-verifying the release pipeline.
>
> Who is affected: users of SendBeam v1.6.0 through v2.2.x who use the
> built-in updater. File-transfer functionality is NOT affected; pairing and
> transfers do not depend on the update system.
>
> What you should do:
>
> 1. Do not install updates delivered by SendBeam versions below v2.3 until
>    you have verified them out-of-band.
> 2. Download the latest release manually from
>    https://github.com/Akshay7273/sendbeam/releases
> 3. Verify it: run `cosign verify-blob --bundle SHA256SUMS.txt.sigstore.json
--certificate-identity-regexp '^https://github\.com/Akshay7273/sendbeam/\.github/workflows/release\.yml@refs/tags/v[0-9]+$'
--certificate-oidc-issuer https://token.actions.githubusercontent.com
SHA256SUMS.txt` then `sha256sum -c SHA256SUMS.txt --ignore-missing`.
> 4. Install the verified release over your existing installation.
> 5. Linux deb users: upgrade via your package repository when announced.
>
> If you cannot verify: wait for the signed installer announcement, or verify
> checksums against the fingerprints published in SECURITY.md from a second
> channel.
>
> Timeline, technical detail, and CVE (if requested) will be published with
> the coordinated advisory.

## 10. What was changed so far (merged)

- **#301 → `731e4f102614`**: retired seed removed from all 14 test-signing
  sites; independent crypto/rand test keys; fail-closed CI guard
  (`scripts/guard-signing-material.sh`, 10 self-tests, mutation-verified)
  covering: retired literal, production pin outside sanctioned verifier,
  production-pin symbol in tests, key-bound RFC 8032 derivation check,
  minisign.pub↔pin consistency. No production key/pin/workflow change.

## 11. Remaining owner approvals (BLOCKERS — nothing below executes without them)

1. Generate + verify replacement production key offline (Phase C step 1).
2. Approve re-pin commit + `minisign.pub` swap (Phase C step 3).
3. Approve release freeze notice + advisory text (§9) + publication timing.
4. Decide update-channel future (§8): keep dark / provision Pages post-v2.3 /
   replace base URL.
5. Optional: request CVE via GitHub Private Vulnerability Reporting.

## 12. Risks that remain after all of the above

- v2.2- clients cannot be retroactively protected from forged updates IF the
  endpoint is ever re-enabled under the old pin — treat re-enablement as an
  attack window until every client is on the new pin.
- The seed remains in Git history and in distributed source archives
  (irreversible without rewrite, which is forbidden and would itself be
  suspicious); the CI guard prevents _new_ occurrences.
- Sigstore provenance exists only from the runs that created it; the
  pre-09-29 asset generations are attested but no longer byte-present.
- MINISIGN_SECRET_KEY (old) remains in GitHub secrets until the owner
  deletes it — deletion is an owner action.
