# Signing-Key Rotation Runbook (SB-SEC02)

Status: **prepared, NOT executed.** Every step below is owner-gated.
Owner: repository owner only. Agent workstations, CI runners, and any
cloud VPS are explicitly excluded from key generation and key custody.

This runbook exists because SB-SEC01 confirmed that the production
update-signing key material was public (the retired fixture seed derived the
pinned public key `BA67BC598735C8DC`). See
[`SECURITY-INCIDENT-SB-SEC01.md`](SECURITY-INCIDENT-SB-SEC01.md).

> **The rotation is not complete until §7 gates pass.** Nothing in this
> repository claims the key has been replaced. Until the re-pin commit lands
> and is verified on a real artifact, the pinned key in
> `packages/engine/updater/verify.go` **is still the compromised key**.

---

## 0. Non-negotiable rules

1. The production private key is generated **only** on an owner-controlled
   trusted machine (§2). Never on this repo's dev workbench, never on a CI
   runner, never on a cloud VPS, never inside an agent session.
2. The private key, its seed, its passphrase, and any recovery material are
   **never** written to this repository, never pasted into an issue or PR,
   never transmitted through chat, and never added as a CI log line.
3. Only **public** material enters git: the base64 public key file, its
   fingerprint, and the verification transcript.
4. The retired key is never trusted again. There is no dual-trust window:
   the client verifier holds exactly one pinned key and has no fallback
   (proven by `packages/engine/updater/sec02_*_test.go`).
5. A failed or partial rotation is a **release blocker**, not a reason to
   restore the old key.

---

## 1. Custody design comparison

Two designs were evaluated. Both are legitimate; they differ in blast radius
and in what "offline" actually means.

### Design A — offline release signing (recommended)

The private key lives on an owner-controlled machine that is offline while
signing. CI builds artifacts and produces `SHA256SUMS.txt`; the owner signs
that checksum file and the update-channel manifests locally, then uploads the
signatures.

| Property | Assessment |
| --- | --- |
| Key exposure surface | Smallest: key never exists in GitHub's secret store, never enters a runner memory space |
| CI compromise impact | An attacker who owns the runner can produce **unsigned** artifacts; they cannot produce a valid signature |
| Release ergonomics | Manual step per release; a human must be present and available |
| Automation ceiling | Lower — no fully automated tag→publish path |
| Recovery | Restore from offline backup; no platform-side re-provisioning |
| Honest claim | "The production signing key has never been present in CI or in any networked system during signing." |

### Design B — protected GitHub Actions signing environment

The key is stored as an Actions secret (environment-scoped), and the signing
job runs inside an environment with required reviewers and release-only
permissions.

| Property | Assessment |
| --- | --- |
| Key exposure surface | Larger: the key exists in GitHub's secret store and is materialized into a runner during signing |
| CI compromise impact | A compromised signing job, a malicious action, or an over-broad secret scope yields **valid signatures** |
| Release ergonomics | Best: tag-driven, repeatable, no human latency |
| Automation ceiling | High — can be fully automated with approvals |
| Recovery | Rotate the GitHub secret; audit the environment's approval log |
| Honest claim | "The signing key is **not** offline. It is held by the CI platform and protected by environment approvals." |

### Recommendation

**Design A for the rotation release (v2.3), with Design B explicitly
rejected for the near term.** Rationale: the incident we are recovering from
is precisely a case of key material existing somewhere it could be read. An
offline signer removes the class, not just the instance.

If the owner later chooses Design B for release velocity, the following must
be true and must be written down: environment-scoped secret, required
reviewers, `release.yml`-only access, no secret exposure to `pull_request`
events, and **no claim anywhere that the key is offline**. Design B also
requires the retired-key rejection gates in §6 to stay in force, because the
blast radius of a CI-side key compromise is larger, not smaller.

---

## 2. Owner-side key generation procedure (design A)

Run this on the trusted machine. Do not run it on the repo workbench.

```bash
# On the owner's trusted, ideally offline machine:
# 1. Build the keygen tool from a known-good checkout, then disconnect.
git clone https://github.com/Akshay7273/sendbeam.git
cd sendbeam && git checkout <TAG_OR_SHA_BEING_RELEASED>
go build -o /tmp/minisign ./scripts/minisign.go

# 2. Generate the keypair into a directory outside any synced folder.
umask 077
mkdir -p ~/secure/sendbeam-signing && cd ~/secure/sendbeam-signing
/tmp/minisign keygen -p minisign-v2.pub -s minisign-v2.key

# 3. Record ONLY the public fingerprint (safe to copy, safe to paste):
go run ./scripts/keycheck.go minisign-v2.pub
```

Expected output shape (values will differ — this is the *only* part that may
leave the machine):

```
key_id_hex=....
public_key_hex=....
public_key_sha256=....
```

> The keygen tool prints the secret seed to stdout for historical reasons.
> After generating, clear your scrollback and shell history
> (`history -c`) before reconnecting the machine to any network.

Custody requirements after generation:

- Two offline copies on encrypted media, stored separately (different
  physical locations).
- At least one copy verified by **restoring and signing a test payload**
  before the media is sealed.
- A written record of the fingerprint and the media locations, stored
  separately from the media.
- The passphrase (if used) memorized or stored in a password manager, never
  in the same place as the key.

---

## 3. Public-key verification and re-pin procedure

The re-pin is a **single commit** that changes exactly two trust-root
artifacts plus documentation. Partial swaps are rejected by CI.

1. Owner supplies the public key file (contents pasted into the PR
   description is acceptable — it is public).
2. Independent verification of the key file (any reviewer, any machine):

   ```bash
   go run ./scripts/keycheck.go /path/to/minisign-v2.pub
   ```

   The `public_key_sha256` value must match the value the owner recorded at
   generation time (§2 step 3), read over a **different channel** than the
   one the key file arrived on.
3. Apply the re-pin:

   ```bash
   # 1. Replace the committed public key file
   cp /path/to/minisign-v2.pub minisign.pub

   # 2. Replace the compiled pin (same value, base64 line only)
   #    packages/engine/updater/verify.go
   #    DefaultMinisignPublicKey = "<public key base64 line>"
   ```

4. Consistency is enforced automatically: `scripts/guard-signing-material.sh`
   fails if `minisign.pub` and `DefaultMinisignPublicKey` disagree.
5. Update `docs/supply-chain.md` and the release notes template so the
   published verification command carries the **new** `-P` value.
6. Run the retirenment gates in §6 before merging.

Merge conditions for the re-pin PR:

- [ ] `keycheck` fingerprint matches the owner's out-of-band record
- [ ] `minisign.pub` == `DefaultMinisignPublicKey`
- [ ] retired-key test suite green (new key accepted; old key rejected)
- [ ] full CI green on the final commit
- [ ] no release is created in the same PR

---

## 4. Old-key retirement checklist

- [ ] Re-pin commit merged (client code + `minisign.pub` + docs)
- [ ] Replacement clients verified to reject old-key signatures (§6)
- [ ] Old `MINISIGN_SECRET_KEY` GitHub secret **deleted** (owner action)
- [ ] Old key fingerprint listed in `SECURITY.md` as RETIRED
- [ ] Any CI/release reference to the retired key removed
- [ ] Advisory published (owner approval) stating rotation is complete
- [ ] Pre-rotation release assets remain published but are annotated as
      signed with the retired key
- [ ] Confirm no automation can re-sign with the retired key

> Deleting the GitHub secret does **not** purge the key from the public git
> history. The retired key must therefore be treated as permanently
> compromised, and the old pin must never be restored.

---

## 5. New update-channel endpoint (Phase C design — not activated)

Requirement: clients built before the rotation (v1.6–v2.2) embed
`https://akshay7273.github.io/sendbeam/updates`. That URL must remain
**unavailable**, including after any future GitHub Pages configuration,
because those clients would accept a forged manifest signed with the retired
key.

Design constraints for the replacement endpoint:

1. **Different path namespace**, not merely a different file at the same
   path. The legacy path stays mapped to nothing (404).
2. **Fixed-host, no wildcard redirects.** Clients must not follow a redirect
   from the update host to an arbitrary host, otherwise endpoint isolation is
   cosmetic.
3. **Per-channel manifests only** (`stable.json`, `beta.json`) plus their
   `.minisig` files. No directory listing, no index page.
4. **HTTPS with a certificate issued to the exact update host.**
5. **Retired-key signatures must fail** even if an attacker manages to place
   a file at the new endpoint.

Legacy-URL non-resuscitation rule: because GitHub Pages serves a project
site at `/<repo>/`, re-enabling Pages for the repository root would make
`/<repo>/updates/` resolvable again **if** any committed `updates/`
directory exists. Therefore:

- The repository must never contain a tracked top-level `updates/` directory
  (guarded by CI, see §6).
- Re-enabling Pages requires a documented route-isolation review first.

Isolation proof lives in the Phase C test suite (§6), which exercises missing
manifests, redirects, legacy-path requests, wrong-channel manifests and
retired-key signatures against a local server.

---

## 6. Verification gates (CI-enforced)

| Gate | What it proves |
| --- | --- |
| `sec02_*` Go tests | New key accepted, retired key rejected, no fallback |
| `keycheck` self-test | Fingerprint tool parses and rejects malformed keys |
| Guard rule (retired pin) | Retired key re-introduction fails CI |
| Guard rule (tracked `updates/`) | Legacy channel path can't silently reappear |
| `verify-release.sh --strict` | Release bundle verifies against the pinned key only |
| Signer/verifier mismatch test | Signing with a key that does not match the pin fails, rather than producing an unverifiable release |

---

## 7. GO / NO-GO gates for the rotation release

**NO-GO** if any of the following is true:

- the pinned key still equals the retired key
- `minisign.pub` and the compiled pin disagree
- any retired-key negative test fails
- the upload endpoint is reachable at the legacy URL
- the release was signed with the retired key
- provenance attestation is missing or unverifiable for a published asset

**GO** only when all of the following hold:

- re-pin merged and verified on a real artifact end-to-end
- retired-key signatures rejected by the shipped client
- new endpoint live, legacy URL confirmed 404
- provenance verified with `gh attestation verify` for every published asset
- advisory approved and published by the owner
- release notes carry the new fingerprint

---

## 8. What this runbook deliberately does not do

It does not generate a key, does not modify the live pin, does not add a
secret, does not touch any endpoint, and does not publish anything. Those are
owner actions by design.
