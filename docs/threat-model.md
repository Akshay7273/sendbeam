# Threat model

Scope: SendBeam transfers a file directly between two peers (browser or terminal). This
document states what we defend against, what we deliberately do not, and why. The wire
protocol it refers to is specified in [`protocol.md`](./protocol.md).

## Security goals

- **Confidentiality** of file contents, filenames, and metadata against the server and any
  network observer, on both the direct and relay paths.
- **Integrity**: the receiver reconstructs exactly the bytes the sender sent, or the
  transfer fails closed. No silent corruption.
- **Peer authentication**: both ends prove knowledge of the invite code, so a malicious or
  compromised server cannot MITM the connection.

## Trust boundaries

- The **signaling/relay server is untrusted** for confidentiality and integrity. It is
  trusted only for availability and correct routing, and even routing is bound to the
  invite code — the server never learns the words, so it cannot silently redirect a peer
  into a handshake it can complete.
- The **network is untrusted** (passive and active attackers).
- Each **peer trusts the other peer** by construction: anyone holding the full invite code
  can authenticate. Authentication proves "you have the code," not a human identity.
- The **local machine and browser are trusted** (out of scope: malware, a hostile browser
  extension, a compromised OS).
- The **durable journal is local, user-editable state** (`docs/adr/0004-durable-journal.md`).
  Its checksum and manifest-fingerprint checks detect corruption, torn writes, and casual
  tampering; they are **not** a trust anchor — anything that can rewrite the file can
  recompute them. Resume-time validation binds journal claims (transfer ID, manifest
  fingerprint, per-file digests, identity envelopes) against authenticated transfer state,
  and the journal never persists raw session key material (no master keys, directional
  keys, live AEAD counters, or credentials; only the opaque versioned `resumeSecret`
  envelope defined by the future resume protocol). Corrupt, torn, unknown, or unsupported
  journal state fails closed and is never partially applied.
- The **local trust database and device identity keys are local, user-protected state**
  ([`docs/trust-model.md`](./trust-model.md)). Device identity is backed by an Ed25519 keypair
  whose private seed is stored in OS-protected credential facilities or restricted filesystem
  permissions (`0600`). Device IDs (`sb-dev-...`) and fingerprints (`SB1-...`) are deterministic
  hashes of the public key; human display labels never authenticate identity. Automated
  acceptance is strictly opt-in per device and bounded to an absolute destination directory
  with full path sanitization. Unpairing or revocation is enforced locally without relying on
  centralized servers.

## Adversaries and mitigations

### Malicious server / active network MITM

The invite-code-authenticated handshake — SPAKE2 (RFC 9382, P-256) with RFC 9382 key
confirmation — runs before WebRTC. Because the server never sees the words, it cannot
derive the SPAKE2 password; a MITM attempt yields a confirmation-MAC mismatch and aborts
closed. SDP and ICE messages are authenticated so a malicious server cannot substitute its
own SDP to MITM the DataChannel:

```
mac = HMAC-SHA256(k_auth, utf8(type) || ":" || u32be(room) || ":" || u32be(seq) || ":" || body)
```

where `k_auth` is retained SPAKE2 key-confirmation material: each peer signs with its own
confirmation key and verifies with the peer's. This binds the DTLS fingerprint, the room,
and message order, so SDP/ICE cannot be swapped or replayed. Confidentiality never relies
on DTLS: the AES-GCM frame layer keyed by the handshake output is the end-to-end guarantee
on both paths. As defense in depth, both peers derive an identical short fingerprint from
the master key that the two humans can compare out of band.

### Passive server on the relay path

Sees ciphertext, message sizes, and timing only. No plaintext, no filenames, no keys. This
is documented, not hidden — see accepted limitations below.

### TURN server

TURN is **optional** (`docs/adr/0003-path-selection.md`). When an operator configures a TURN
server, it acts as a third-party relay for WebRTC datagrams: it sees only encrypted
AEAD/DTLS datagrams, never plaintext file contents, filenames, or keys (the application-layer
AES-GCM frame is the end-to-end confidentiality guarantee on every candidate). Like the relay,
the TURN server observes connectivity metadata (source/destination addresses and ports,
timing) that a passive network observer would see anyway. Because the authenticated SDP/ICE
exchange binds the DTLS fingerprint and negotiating a second MITM SDP is impossible, a TURN
server that dropped or tampered with datagrams would only cause a connectivity failure, not a
confidentiality or integrity break. Operators may use short-lived TURN credentials, which
clients honour via the 15-minute runtime-ICE-config TTL (`HOSTING.md`).

### Replay / reordering / tampering

AES-256-GCM with a per-direction monotonic nonce counter; the frame header is the GCM AAD,
binding each frame to its position (file, block, offset, length). A reused counter is
refused rather than risk nonce reuse. Any tampering fails the GCM auth tag; a bad per-block
SHA-256 escalates to abort (no blind retry). Resume state is a claim, not a trust anchor: a
receiver only applies a locally restored seed after binding it to the authenticated
manifest's canonical fingerprint (exact file set and block geometry) and failing closed on
any violation, never clamping an out-of-range claim; the sender likewise rejects any
`resume_state` that does not match its own manifest (unknown, duplicate, or missing file
entries, out-of-range `haveBlocks`, a fingerprint mismatch, or a conflicting duplicate), so a
malicious or stale peer cannot steer a resumed transfer into writing the wrong bytes or
skipping unverified data.

### Code leakage

Anyone who obtains the full invite code can join until the first peer pairs or the room is
reaped. Mitigations: strictly 1:1 pairing (a second `join` on a live room is refused with
`room_full`), rooms reaped after the signaling idle timeout (default 10 minutes), and — in
the browser — a fragment-only code kept out of `Referer` and server logs via
`Referrer-Policy: no-referrer` and fragment semantics. Because the code is a low-entropy
human string, its security rests on the online, single-attempt nature of SPAKE2 (the server
cannot brute-force it offline) combined with 1:1 pairing and the short room lifetime, not
on the code's length.

### Denial of service & anti-abuse defenses

Per-session relay queue, bandwidth, frame-size, and lifetime-bytes caps
(`SENDBEAM_RELAY_*`, see `HOSTING.md`); message-size and per-connection message-rate caps;
per-IP connection-rate limits and active connection quotas (`SENDBEAM_MAX_CONNS_PER_IP`);
per-IP room creation rate limiting; failed-join penalty buckets to mitigate online room-code
brute-force guessing; global room and connection capacity ceilings; and a periodic room reaper on
the idle timeout. A WSS origin allowlist on the signaling upgrade (`SENDBEAM_ALLOWED_ORIGINS`)
blocks cross-site socket abuse, and trusted reverse-proxy CIDR filtering (`SENDBEAM_TRUSTED_PROXIES`)
prevents client IP spoofing via forged `X-Forwarded-For` headers. All limits are operator-tunable
and defaults keep server memory strictly bounded under load.

### Malicious sender (receiver-side safety)

Filenames are sanitized on receipt to prevent directory traversal; a per-transfer
file-count cap, quota checks, and the in-flight block bound (`DEFAULT_INFLIGHT_BLOCKS = 8`)
prevent resource exhaustion; the receiver confirms before writing outside OPFS; per-block
and whole-file digests are verified before completion is reported.

### Web-facing hardening & zero-PII observability

The HTTP surface sets a strict CSP (`default-src 'self'`, `connect-src 'self' wss: https:`,
`script-src 'self' 'wasm-unsafe-eval'`, `object-src 'none'`, `base-uri 'none'`,
`frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and
`Referrer-Policy: no-referrer`.

The server enforces a strict **Zero-PII Observability Guarantee**:

- Structured server logs (`SENDBEAM_LOG_FORMAT=text|json`) record only room numbers, error codes, and message counts — never client IP addresses, invite words, filenames, payload plaintext, or cryptographic keys.
- Prometheus metrics (`GET /metrics`) expose only aggregate gauges and monotonic counters (e.g. `sendbeam_rooms`, `sendbeam_relay_bytes_total`, `sendbeam_errors_total{code=...}`) with low-cardinality label dimensions — zero client identifiers or user data.

## What the server can and cannot see

- **Cannot see:** the invite words, file bytes, filenames, digests, session keys, client IPs in metrics/logs, or frame plaintext contents.
- **Can see:** the room number, socket metadata, SDP/ICE needed to route, and — on the
  relay path only — ciphertext byte counts and timing.

### Relay Metadata Defenses (v1.7)

In v1.7, SendBeam introduces active defenses against metadata leakage on the relay path:

| Metadata Property           | v1.6 (Baseline)                      | v1.7 (With Defenses)                                                                    | Residual Observable Surface                                   |
| --------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **Frame Ciphertext Length** | Exact payload length + 16 B AEAD tag | Discrete power-of-two buckets ($256, 512, \dots, 65535$) via authenticated zero-padding | Only coarse bucket size                                       |
| **Transmission Timing**     | Immediate packet bursts              | Randomized sender-side scheduling jitter (configurable up to 15ms)                      | Fine-grained burst signatures blurred; macro duration visible |
| **Server Logging**          | Zero per-frame logging               | Zero per-frame logging (audited via automated tests)                                    | No frame payloads, tags, or headers logged                    |
| **Server Metrics**          | Aggregate byte counter               | Aggregate byte counter                                                                  | Only total relayed bytes per server                           |
| **Room Association**        | 2 sockets per room                   | 2 sockets per room                                                                      | Socket correlation remains observable                         |

## Accepted limitations

- **Relay socket correlation and macro traffic volume (v1.7 / V17-PR04):** While frame padding and sender-side timing jitter prevent fine-grained payload fingerprinting and burst timing analysis, the relay server necessarily observes that two client sockets belong to the same active room. Furthermore, aggregate ciphertext volume and macro session duration remain observable to the relay operator.
- **Traffic padding scope (v1.7 / ADR 0009):** When negotiated via the `padding` capability (or `--private` flag), all frame ciphertexts are quantized into discrete power-of-two buckets ($256, 512, \dots, 65535$ bytes) with authenticated zero-padding, preventing fine-grained fingerprinting of manifest and control frames. However, in unpadded mode (or when communicating with legacy v1.6 peers), exact payload lengths remain visible on the wire.
- **Whoever holds the code can impersonate a peer** until first-pair or room reaping. The
  human fingerprint check does not close this — a code holder can complete the handshake
  and produce the matching fingerprint — so the real mitigations are careful code
  distribution, single-use pairing, and the short room lifetime.
- **Endpoint compromise is out of scope.** A compromised browser, extension, or OS can read
  plaintext before or after transfer; no wire protocol can prevent that.

## Verification

Negative crypto tests are part of the suite: a wrong invite code fails closed; a tampered
`pake` element aborts; a tampered or replayed SDP MAC is rejected; a reused GCM nonce is
rejected; a bad block hash aborts without retry; two sessions sharing the same code derive
different master keys (ephemeral SPAKE2 freshness); a forged `resume_state` is rejected (bad
transfer id, mismatched or malformed manifest fingerprint, unknown/duplicate/missing file
entries, or out-of-range `haveBlocks` all fail closed on both the sender and receiver).
Cross-language vector tests keep the TypeScript and Go implementations byte-identical, and
the test-vector suite (KATs + a full transfer vector) is published under
`docs/test-vectors/` for independent reimplementation. Before public release the crypto
and server are security-reviewed and the JS/Go dependencies audited.

- **Opaque Rendezvous Handles:** Pairwise handles are derived via `HMAC-SHA256(k_pair, "sendbeam/2 rendezvous-handle:" || epoch)` rotating every 15 minutes. The signaling server sees connection attempts for a random-looking 32-byte hex string, but cannot link distinct handles across epochs, determine the underlying device identities, or associate them with account records.
- **Blinded LAN Beacons:** UDP broadcast/multicast beacons contain only ephemeral random nonces, port numbers, and truncated 16-byte HMAC tags (`HMAC(k_pair, nonce || epoch)`). Passive network observers on the local Wi-Fi see pseudorandom beacons without plaintext device names, fingerprints, or transfer metadata.

## Persistent Device Trust & Browser Storage Boundaries (v1.5 / v1.8)

- **Local Trust Storage Isolation:** Device identities (`identity.key` on CLI/Desktop, `sendbeam-identity` on Web), paired trust records (`trust.json` / `sendbeam-trust`), and pair credentials (`secrets.json` with `0600` permissions / `sendbeam-secrets`) are maintained strictly on the local device. No global account database or centralized directory exists.
- **Capability Gating:** Persistent pairing is gated on modern WebCrypto subtle API and IndexedDB storage. In environments lacking secure storage, persistent pairing is disabled cleanly and one-time room-code transfers remain active.
- **Adversarial Attack Matrix:** Automated regression test suites in Go (`packages/wire/attack_matrix_test.go`, `packages/engine/trust/attack_matrix_test.go`, `packages/engine/updater/attack_matrix_test.go`) and TypeScript (`packages/protocol/src/attack-matrix.test.ts`) continuously exercise and prove resistance against 20 comprehensive threat-model attack vectors:

### Comprehensive 20-Vector Adversarial Attack Matrix

| #      | Attack Vector                                 | Attacker Objective / Threat Scenario                                                                | Defense Mechanism                                                                                                     | Go Test Cross-Reference                                       | TypeScript Test Cross-Reference                                |
| ------ | --------------------------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------- |
| **1**  | **Public Key Mismatch / Stolen DB**           | Inject modified public key into trust store for genuine device ID, or swap device ID.               | Canonical device ID derivation (`sb-dev-<sha256(pubkey)>`) and public key mismatch rejection on record load.          | `wire/attack_matrix_test.go`<br>`trust/attack_matrix_test.go` | `protocol/src/attack-matrix.test.ts` (Vector 1)                |
| **2**  | **Replay Attack & Stale Challenges**          | Capture valid handshake initiation or response and replay to impersonate a trusted peer.            | Ephemeral 32-byte nonces, timestamp skew bounds (±5m), and monotonic challenge replay prevention.                     | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 2)                |
| **3**  | **Relay / Signaling MITM & Key Substitution** | Intercept ephemeral key exchange, substitute keys or modify directional auth payloads.              | Transcript binding to static identity keys; AES-GCM additional authenticated data (AAD) authentication failure.       | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 3)                |
| **4**  | **Presence Beacon Replay**                    | Capture and replay rendezvous handles or LAN beacon packets across time epochs.                     | 15-minute epoch quantization; handles and HMAC beacon tags expire outside active ±1 epoch window.                     | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 4)                |
| **5**  | **Display Name Spoofing**                     | Claim trusted peer's display name or local label without holding cryptographic private key.         | Trust records and authorizations bind strictly to `DeviceId` and Ed25519 identity key, never display labels.          | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 5)                |
| **6**  | **Downgrade Attack & Capability Stripping**   | Strip security capabilities (e.g., trusted auth, session resumption) from negotiation offer.        | Enforces authenticated capability negotiation; stripping security capabilities aborts session.                        | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 6)                |
| **7**  | **Stale / Revoked Pair Credential**           | Use previously valid but revoked pair credential to initiate trusted transfer.                      | Trust store flags `revoked=true`; pairing and trusted-session handshakes fail closed on revoked peers.                | `wire/attack_matrix_test.go`<br>`trust/attack_matrix_test.go` | `protocol/src/attack-matrix.test.ts` (Vector 7)                |
| **8**  | **Auto-Accept Path Traversal**                | Transmit malicious filenames (`../../etc/shadow`, illegal characters) to escape transfer directory. | `NormalizeTransferPath` enforces containment within root destination; rejects escapes and control chars.              | `wire/attack_matrix_test.go`<br>`trust/attack_matrix_test.go` | `protocol/src/attack-matrix.test.ts` (Vector 8)                |
| **9**  | **One-Time Transfer Trust Pollution**         | Coerce one-time transfer into mutating persistent trust store or persisting credentials.            | Ephemeral transfer sessions bypass trust store writes entirely; zero disk or IndexedDB residue.                       | `trust/attack_matrix_test.go`                                 | `protocol/src/attack-matrix.test.ts` (Vector 9)                |
| **10** | **Forged Revocation Records**                 | Construct forged revocation record with invalid Ed25519 signature to distrust peers.                | `VerifyRevocation` checks cryptographic signature against revoker's pinned public key; fails closed.                  | `trust/attack_matrix_test.go`                                 | `protocol/src/attack-matrix.test.ts` (Vector 10)               |
| **11** | **Revocation Sequence Rollback**              | Replay older or lower sequence number revocation record to roll back trust state.                   | Monotonic sequence enforcement: incoming record `Seq <= current.Seq` is rejected with rollback error.                 | `trust/attack_matrix_test.go`                                 | `protocol/src/attack-matrix.test.ts` (Vector 11)               |
| **12** | **Unknown / Revoked Revoker Records**         | Submit validly signed revocation record from a device not in trust store or already revoked.        | Trust store requires revoker to be an active, unrevoked trusted device in the local trust store.                      | `trust/attack_matrix_test.go`                                 | `protocol/src/attack-matrix.test.ts` (Vector 12)               |
| **13** | **Padding-Oracle Probe**                      | Probe receiver with malformed lengths, non-zero padding bytes, or bit-flipped AEAD envelopes.       | Constant-time validation; non-zero padding bytes reject with malformed frame; AEAD failure precedes depad.            | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 13)               |
| **14** | **Bucket-Downgrade Coercion**                 | Strip padding capability to leak file transfer sizes via variable frame lengths.                    | Private session policy mandates `PaddingCapability` / `FEATURE_PADDING`; unpadded frames rejected.                    | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 14)               |
| **15** | **Update-Manifest Replay**                    | Replay validly signed older `stable.json` manifest to roll back native client to vulnerable build.  | Version monotonicity check in updater `Check()` and `Apply()`; rejects downgrades (_Go native CLI/Desktop boundary_). | `updater/attack_matrix_test.go`                               | `protocol/src/attack-matrix.test.ts` (Vector 15, doc boundary) |
| **16** | **Revocation Race Condition**                 | Race in-flight trusted transfer session with concurrent incoming revocation record.                 | Coordinator sets `IsTrusted: false` immediately; session and subsequent transfer authorizations abort.                | `trust/attack_matrix_test.go`                                 | `protocol/src/attack-matrix.test.ts` (Vector 16)               |
| **17** | **Revocation Domain Monotonicity**            | Replay revocation across domains or attempt sequence rollback during mesh sync.                     | Domain-separated challenges (`sendbeam/2 revocation-record:`); strict monotonic sequence validation.                  | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 17)               |
| **18** | **Relay Frame Corruption / Reorder**          | Relay server flips ciphertext bits, delays/reorders sequenced frames, or truncates payload.         | AES-GCM AEAD envelope integrity fails on corruption; monotonic counter window rejects reordered frames.               | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 18)               |
| **19** | **Durable Journal Tampering**                 | Corrupt transfer journal JSON, truncate write, alter manifest fingerprint, or falsify blocks.       | `DecodeJournal` validates JSON, schema version, checksum, fingerprint match, and committed block bounds.              | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 19)               |
| **20** | **Pairing Confirmation Misuse**               | Replay SPAKE2+ confirmation tag across sessions, substitute peer ID, or forge tag.                  | HMAC-SHA256 over `DomainPairingConfirm` and peer device ID; verified before any trust store write.                    | `wire/attack_matrix_test.go`                                  | `protocol/src/attack-matrix.test.ts` (Vector 20)               |
