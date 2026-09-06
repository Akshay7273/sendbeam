# SendBeam v1.8.1 — Safety Patch Release Gate

The v1.8.1 milestone (**Safety Patch & Honest Capability Matrix**) gates release on the critical security remediations, capability boundary honesty corrections, and verification checks below, each verified against merged `main`.

---

## 1. Safety Patch Deliverables

| Logical ID    | Deliverable                                 |             Status              | Evidence                                                                                                                                                                                                                                                                                                                                        |
| :------------ | :------------------------------------------ | :-----------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **V18H-PR01** | **Secret-Free Public JSON and Diagnostics** | **MERGED** (PR #176, `e6d144d`) | Public DTO (`transfer.PublicOutcome`) exposes only safe transfer metadata (`name`, `size`, `digest`, `path`, `files`). Sensitive cryptographic state marked `json:"-"` across wire and engine. Redacted diagnostics prevent credential leaks in terminal and log outputs.                                                                       |
| **V18H-PR02** | **Literal-Text Desktop Rendering**          | **MERGED** (PR #177, `de52250`) | Eliminated all 14 `innerHTML` assignments in desktop Wails shell (`apps/desktop/frontend/dist/index.html`). Remote filenames, error strings, and status updates render inertly as literal DOM text nodes (`textContent`, `replaceChildren`, `createTextNode`).                                                                                  |
| **V18H-PR03** | **Allowlisted PWA Caching & Isolation**     | **MERGED** (PR #178, `1597f46`) | Scoped Service Worker cache pruning on activation strictly to SendBeam shell caches (`sendbeam-shell-*`), preserving all unrelated origin caches. Intercepts and caches only verified static shell assets; bypasses query parameters (`?code=...`), dynamic endpoints, Range requests, and `/sw.js`. Defers updates while transfers are active. |
| **V18H-PR04** | **Honest Capability Matrix & Patch Gate**   |           **CURRENT**           | Corrected forward-secrecy and network-anonymity claims across documentation and code comments. Documented exact runtime boundaries for WebKit CI emulation, OPFS memory pressure, traffic padding negotiation, and 32-bit archive limits. Verified safety fixes and ordinary transfer stability.                                                |

---

## 2. Honest Capability Matrix & Trust Boundaries

Following systematic security review, the following capabilities and boundaries are explicitly defined:

### 2.1 Cryptographic Session Key Derivation (`sendbeam/2`)

- **Implemented Behavior:** Pairwise session keys (`k_i2r`, `k_r2i`) are derived via `HMAC-SHA256(k_pair, Ephem_A || Ephem_B || Nonce_A || Nonce_B)` and `HKDF-SHA256`.
- **Guarantees:** Mutual peer authentication, transcript binding, replay protection, and clock skew bounding (±5 min).
- **Boundary & Limitation:** Because ephemeral values are authenticated via `k_pair` without an ephemeral Diffie-Hellman (ECDH) exchange, compromise of `k_pair` permits retroactive decryption of past session recordings. It does **not** provide forward secrecy.
- **Roadmap:** A reviewed, versioned authenticated ephemeral Diffie-Hellman key exchange (X25519) providing true forward secrecy is scheduled for v1.9 (V19-PR01 / V19-PR02).

### 2.2 Network Presence & Rendezvous Handles

- **Implemented Behavior:** 15-minute epoch-rotated blind handles (`HMAC(k_pair, "sendbeam/2 rendezvous-handle:" || epoch)`).
- **Guarantees:** Third parties and the signaling server cannot index or harvest a global directory of registered devices from handle strings alone.
- **Boundary & Limitation:** Opaque handles do **not** provide transport-layer network anonymity. The signaling server and upstream network observers observe client TCP/WebSocket connections, public IP addresses, and message timing.

### 2.3 Wire Traffic Padding Policy

- **Implemented Behavior:** Frame payloads are quantized into power-of-two buckets ($256..65535$) when negotiated.
- **Guarantees:** Obfuscates exact file sizes and chunk boundaries when both peers support and advertise `padding`.
- **Boundary & Limitation:** In v1.8, wire padding is negotiated opportunistically. `--private` advertises padding, but if the remote peer lacks the capability, transfers proceed unpadded. Strict host-level policy (refusing transfers when private mode is requested against an unpadded peer) is scheduled for v1.9 (V19-PR11).

### 2.4 Browser Platform & Storage Ceilings

- **WebKit / iOS Testing:** CI tests execute Playwright on Linux using the WebKit engine with mobile viewport emulation. This demonstrates browser engine compliance, but is not physical iOS hardware testing.
- **OPFS Memory Bounds:** Transfers stream blocks to disk to prevent JS heap accumulation. While bounded for tested workloads, peak memory on physical mobile devices remains subject to OS jetsam constraints.
- **ZIP Archive Sinks:** In-browser archive generation uses standard 32-bit ZIP formats capped at 4 GiB. Streaming ZIP64 with arbitrary file counts and 64-bit sizes is scheduled for v2.0 (V20-PR05).

---

## 3. Ordinary Transfer & Safety Verification

All ordinary transfer paths and safety remediations have been verified:

1. **Ordinary SPAKE2 Transfers (`sendbeam/1`):**
   - Direct WebRTC DataChannel transfers: Verified.
   - Encrypted WebSocket relay fallback: Verified.
   - SHA-256 end-to-end whole-file digest verification: Verified.
2. **Safety Remediations:**
   - CLI JSON outputs contain zero secrets or key material: Verified (`diagnostics.test.ts`, CLI tests).
   - Desktop frontend contains zero `innerHTML` or script injection sinks: Verified (`render_safety_test.go`, JSDOM suite).
   - PWA Service Worker caches only static shell files, preserves unrelated caches, and defers activation during transfers: Verified (`sw.test.ts`, Playwright e2e).
   - Wire padding negotiation helper (`NegotiatePadding` / `isPaddingNegotiated`): Verified in Go and TypeScript suites.

---

## 4. Release Checklist

- [x] V18H-PR01 merged to main (`e6d144d`)
- [x] V18H-PR02 merged to main (`de52250`)
- [x] V18H-PR03 merged to main (`1597f46`)
- [x] V18H-PR04 honest capability matrix and patch gate implemented
- [x] Documentation synchronized across `README.md`, `protocol.md`, `trust-model.md`, `compat-matrix.md`, `threat-model.md`
- [x] Workspace verification passes 100% green: `format:check`, `lint`, `typecheck`, `test`, `build`, Go test `-race`, version metadata
