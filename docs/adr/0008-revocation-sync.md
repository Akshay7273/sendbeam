# ADR 0008: Signed Revocation Records & Mesh Revocation Sync

**Status:** Accepted  
**Date:** 2026-08-30  
**Context:** SendBeam v1.7 Milestone V17-PR01  
**Deciders:** Core Engineering Team

---

## 1. Context & Problem Statement

In SendBeam v1.5/v1.6, persistent device identities (`DeviceID = sb-dev-...` derived from Ed25519 public keys) and pairwise trust relationships (`trust.json`) were established via one-time SPAKE2 pairing ceremonies.

However, the trust model maintained an **accepted honest limitation** (documented in `docs/trust-model.md` §4.1):

> _Revoking a device only protects the revoking side. There is no centralized server revocation list (CRL) or account-wide revocation. If Device A revokes Device B, Device A rejects Device B, but Device C (also owned by the same user or in the same mesh) does not know that Device B was revoked until manually revoked on Device C._

Our goal in v1.7 is to close this limitation: when an owner revokes a device on any of their machines, **their other devices must learn about it automatically, opportunistically, and verifiably** without introducing central servers, accounts, or global CRL infrastructure.

---

## 2. Design Decision

### 2.1 Canonical Signed Revocation Records

A revocation record is an immutable, canonical, domain-separated statement signed by the revoking device's Ed25519 private identity key:

$$\text{RevocationRecord} = (\text{RevokerDeviceID}, \text{RevokedDeviceID}, \text{Seq}, \text{Timestamp}, \text{Signature})$$

#### Challenge Specification:

$$\text{Challenge} = \text{"sendbeam/2 revocation-record:"} \parallel \text{RevokerDeviceID} \parallel \text{RevokedDeviceID} \parallel \text{BigEndian}(\text{Seq}) \parallel \text{Timestamp}$$

- **Domain Separation:** `"sendbeam/2 revocation-record:"` (30 bytes ASCII).
- **RevokerDeviceID:** 71-character canonical identifier (`sb-dev-` + 64 hex characters) matching `sha256(RevokerPubKey)`.
- **RevokedDeviceID:** 71-character canonical identifier of the target distrusted device.
- **Seq:** 64-bit unsigned monotonic integer (`uint64`, 8 bytes big-endian) to prevent replay/rollback attacks and enforce strict ordering.
- **Timestamp:** ISO 8601 / RFC 3339 UTC string (e.g. `"2026-08-30T12:00:00Z"`).
- **Signature:** 64-byte raw Ed25519 signature encoded as 128 lowercase hex characters.

### 2.2 Opportunistic Propagation over `sendbeam/2` Trusted Sessions

1. **Zero New Infrastructure:** Revocation records propagate opportunistically over existing authenticated `sendbeam/2` trusted sessions (piggybacked in `TrustedAuthInit` and `TrustedAuthResponse` frames).
2. **Backwards Compatibility:** Old peers (v1.6) ignore the optional `revocations` JSON field and negotiate normally.
3. **Symmetric Exchange:** When Device A and Device C establish a trusted session, each transmits all active valid revocation records known to its local trust store.

### 2.3 Verification & Ingestion Rules (Fail-Closed)

When Device C receives a `RevocationRecord` claiming Revoker A revoked Device B:

1. **Direct Trust Prerequisite:** Device C checks if Revoker A is registered in Device C's local trust database (`trust.json`). If Revoker A is unknown or unpaired, the record is **ignored fail-closed**.
2. **Revoker Trustworthiness:** Device C checks if Revoker A is currently active (`revoked: false`). Revocation claims submitted by an already-revoked device are **rejected fail-closed**.
3. **Cryptographic Signature Verification:** Device C retrieves Revoker A's stored Ed25519 public key and verifies the Ed25519 signature over the canonical challenge. Any signature mismatch or malformed record causes **immediate rejection**.
4. **Monotonic Sequence Enforcement:** If Device C already has a revocation record for Device B from Revoker A, the incoming `Seq` must be strictly greater than the stored sequence (`Seq > StoredSeq`). Lower or equal sequence numbers are rejected to prevent replay/rollback attacks.
5. **Timestamp Skew Bounding:** The record timestamp must fall within the allowed maximum clock skew window (±5 minutes from current UTC time, or within plausible past boundaries).
6. **State Mutation:** If all checks pass and Device B exists in Device C's trust database:
   - `DeviceB.Revoked = true`
   - `DeviceB.RevokedAt = Timestamp`
   - `DeviceB.RevokedBy = RevokerDeviceID`
   - `DeviceB.RevocationSeq = Seq`
   - `DeviceB.RevocationSig = Signature`
   - Atomic flush to `trust.json`.

---

## 3. Scope Honesty & Threat Model Alignment

- **Owner Mesh Synchronization:** This mechanism synchronizes the view of an owner's trusted devices that are mutually paired.
- **What it DOES protect against:**
  - Prevents a compromised/revoked device from connecting to other paired devices in the mesh as soon as those devices sync with any revoking peer.
  - Forged revocation claims are cryptographically impossible without the revoker's private key.
  - Replay and sequence rollback attacks fail closed.
- **What it DOES NOT do (Documented Limitation):**
  - It does not and cannot force a physically compromised or revoked device to forget existing files or delete its local database.
  - Offline devices only learn about revocations upon their next trusted session with an active peer.

---

## 4. Consequences & Invariants

- **Zero Breaking Protocol Changes:** `sendbeam/1` (one-time transfers) and `sendbeam/2` (trusted sessions) remain 100% wire compatible with v1.6 peers.
- **Deterministic Cross-Language Consistency:** Go (`packages/wire`) and TypeScript (`packages/protocol`) share identical deterministic test vectors in `packages/wire/testdata/revocation-vectors.json`.
- **Auditable Provenance:** CLI `sendbeam devices` and Desktop/Web UI display whether a device was revoked locally or via mesh sync (including revoker identity).
