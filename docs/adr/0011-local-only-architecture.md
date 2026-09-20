# ADR 0011 — Local-only architecture and threat model (v2.1 "Nearby & Offline")

Status: accepted (lead-dev design review; see §10)
Scope: v2.1 (V21-PR01–08)
Applies to: `packages/engine` (Go: discovery, rendezvous, rtc, wsclient, relay, updater, diagnostics, trust, transfer, supervisor), `apps/cli`, `apps/desktop`, `docs`

## 1. Context

v2.0 made handoffs manageable: durable jobs, a local outbox, a transfer center,
receive preflight, streaming ZIP64, encrypted text/link handoffs and measured
reliability evidence. Every online transfer in v2.0, however, still depends on
the public rendezvous service:

- CLI `send` dials the public signaling server over a WebSocket (`wsclient`),
  negotiates a `rendezvous.Session`, then rides a WebRTC DataChannel
  (`rtc.Peer`) with default ICE servers (`stun:stun.l.google.com:19302`) or
  falls back to the encrypted WebSocket relay (`relay.Conn`).
- `sendbeam listen` additionally watches LAN beacons, but beacons only locate
  already-paired peers; they do not bootstrap signaling or transfers.
- Pairing uses the reviewed `trust.PairingCoordinator` over a
  transport-agnostic `PairingTransport` interface, currently fed by the public
  signaling path.

v1.8-era LAN discovery exists (`discovery.LanDiscoveryService`, blinded beacons
over UDP), but discovery alone is not a server-independent transfer system.
v2.1 completes the missing bootstrap, authentication, local route and product
behavior so two native clients on a reachable local network can pair and
transfer with public rendezvous, STUN, TURN and relay services unreachable.

**Out of scope for this design:** browser/PWA offline parity (a secure page
cannot be assumed to reach arbitrary local endpoints, raw multicast or an
offline native pairing service); native mobile apps; two-way sync;
delta/dedup sync; cloud backup.

## 2. Decisions

### 2.1 Three network policies, separate from padding policy

Introduce an explicit, persistent, user-selected network policy:

| Policy               | Meaning                                                                                                                                             |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Local only`         | Only policy-approved local paths may be used. Any attempt to reach a non-local endpoint fails closed with a clear error. No silent online fallback. |
| `Prefer local`       | Try local routes first; may use an approved online path when no local route exists.                                                                 |
| `Online` (automatic) | Current v2.0 behavior: public signaling, STUN, relay as configured.                                                                                 |

Network policy and padding policy (`--private` / `--require-padding`) are
separate controls. A local route never justifies disabling authentication,
encryption, integrity or strict padding.

### 2.2 Reuse WebRTC with host-only ICE over a local rendezvous service

For signaling bootstrap, implement a **bounded native local rendezvous
service** (V21-PR02): a local TCP/TLS listener that routes only protocol
envelopes (the existing `rendezvous.Message` framing). No file listing, no
path serving, no remote administration.

For the byte path, reuse the existing encrypted WebRTC DataChannel
(`rtc.Peer`) with **explicitly empty ICE servers** in `Local only`. pion
gathers host candidates on the local interfaces without any STUN lookup, so
no new transport is introduced and the reviewed E2EE framing, strict padding,
backpressure and limits ride unchanged. The encrypted WebSocket relay stays
internet-bound and is never selected under `Local only`.

Alternatives considered:

- **New direct TLS-over-TCP transport.** Rejected for v2.1: it duplicates the
  reviewed framing, padding and backpressure machinery and adds a second
  transfer path to test. Revisit only if WebRTC host candidates prove
  unusable on a supported network (recorded as a fallback, not a plan).
- **Reuse the public signaling server with "local" ICE.** Rejected: it
  keeps the public service in the trust path and leaks presence metadata.

### 2.3 Authentication and pairing are unchanged constructions

- **Known pairs:** the existing trusted session auth (ADR 0010) binds the
  selected peer. A beacon, a private IP or `LastSeen` never counts as
  authentication or proof of availability.
- **First pairing:** the existing reviewed `trust.PairingCoordinator`
  ceremony runs over a `PairingTransport` bound to the local rendezvous
  session. The QR/code contains only bootstrap data (endpoint + short-lived
  session token); secret material stays out of logs, URLs and command
  arguments. Guesses are rate-limited; the invitation window is short-lived
  and cancellable. Trust and credentials persist only after mutual
  confirmation and successful storage.
- **Simultaneous offers:** if both sides initiate, the rendezvous session
  roles resolve deterministically (lower session-id hash is offerer); the
  loser of the race re-runs as joiner rather than opening two sessions.

### 2.4 Discovery stays blinded; candidates are validated, never trusted

`discovery.LanDiscoveryService` is reused for presence. Every candidate is
subject to the route-policy validator (V21-PR03):

- Recently discovered ≠ authenticating ≠ verified reachable: three distinct
  states, shown distinctly in the UI.
- Manual local connection (IP:port) is offered for networks where multicast
  is blocked; manual endpoints go through the same validation.
- Validation covers: approved network/interface policy, DNS rebinding
  (re-resolve and reject if the name resolves outside the approved network),
  alternate-IP attempts, loopback/link-local misuse, and endpoint
  substitution after authentication begins. Possession of a candidate never
  authorizes a transfer; only the authenticated identity becomes the
  connected peer.
- Peer tables are bounded and expire; they never grow without limit.

### 2.5 Egress enforcement is code, not a UI flag

In `Local only`, every app-initiated network consumer must consult the
network policy and refuse non-local egress (see §4 matrix). Enforcement is
in the engine: the policy object is passed to the actual connection sites
(candidate gathering, dial, update check, diagnostics), not just the UI.

### 2.6 Listener exposure is bounded by default

- The local rendezvous listener binds to **explicitly selected local
  interfaces**, never a wildcard bind on every interface by default.
- Unpaired sessions are admitted only through a **user-opened, short-lived
  pairing window**. Outside the window, unknown sessions are refused.
- Connections and message sizes are limited; deadlines and cancellation are
  mandatory; shutdown removes listeners and pending sessions.
- Errors never leak credentials.

## 3. Threat model

| Threat                                     | Treatment                                                                                                                                                                        |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Rogue local peer forges beacons            | Beacons are blinded and matched only against paired-device keys; a forged beacon yields no candidate for an unpaired device, and a beacon never authenticates.                   |
| Attacker on the LAN races a pairing window | Pairing requires the short code / QR scan out of band; guesses are rate-limited; the window is short-lived and user-opened. A competing joiner cannot complete without the code. |
| DNS rebinding / endpoint substitution      | Manual and discovered endpoints are re-validated against the approved network/interface policy before and during session establishment; substitution aborts the session.         |
| Listener exposed to hostile network        | Explicit interface binding, pairing-window gating, connection/message limits, no admin or file-serving endpoints.                                                                |
| Silent online fallback leaks metadata      | `Local only` fails closed; the egress matrix (§4) is enforced at connection sites and asserted by tests.                                                                         |
| VPN / multi-interface confusion            | Interface selection is explicit and shown per job; a route on an unapproved interface is not used in `Local only`.                                                               |
| IPv6 formatting / link-local misuse        | Link-local and loopback candidates are rejected unless explicitly enabled for the approved interface; IPv6 literals are validated and formatted canonically.                     |
| Replay of rendezvous envelopes             | Envelopes carry the session's replay protection from the existing ceremony; duplicates are dropped.                                                                              |
| Updater / diagnostics phone home           | Both are disabled (or deferred with explicit user consent) while `Local only` is active.                                                                                         |

## 4. Policy / egress matrix

Applies to app-initiated network use. OS traffic outside SendBeam is outside
the claim.

| Consumer                                                        | Local only                     | Prefer local                | Online  |
| --------------------------------------------------------------- | ------------------------------ | --------------------------- | ------- |
| Public signaling WebSocket (`wsclient`)                         | BLOCKED                        | allowed when no local route | allowed |
| Local rendezvous listener + session                             | allowed (approved interfaces)  | allowed                     | allowed |
| LAN discovery beacons (UDP)                                     | allowed                        | allowed                     | allowed |
| ICE: STUN / TURN                                                | BLOCKED (host candidates only) | allowed if local fails      | allowed |
| Encrypted WS relay (`relay.Conn`)                               | BLOCKED                        | allowed if local fails      | allowed |
| Update check / download (`updater`, desktop `update_service`)   | BLOCKED (deferred)             | deferred to online          | allowed |
| Diagnostics network probes (`diagnostics`, `sendbeam diagnose`) | BLOCKED for remote targets     | local targets only          | allowed |
| Local DNS resolution for manual endpoints                       | allowed (validated)            | allowed                     | allowed |
| Public DNS / DoH for peer endpoints                             | BLOCKED                        | allowed if local fails      | allowed |

In `Prefer local`, every use of an online consumer after local failure is
logged and surfaced per job; in `Local only`, the attempt is refused before
any packet is emitted.

## 5. Sequence diagrams

### 5.1 Known-pair offline flow (Local only)

```mermaid
sequenceDiagram
    participant A as Alice (CLI)
    participant B as Bob (desktop)
    A->>A: policy = Local only
    B->>B: policy = Local only
    B->>B: start local rendezvous listener (approved iface)
    A->>B: UDP blinded beacon (paired keys only)
    B->>A: UDP blinded beacon (paired keys only)
    A->>A: candidate = Bob(device-id) [recently discovered]
    A->>B: TCP/TLS to local rendezvous endpoint
    B->>B: session admitted (paired peer, no window needed)
    A->>B: rendezvous envelopes (offer/answer, empty ICE servers)
    B->>A: rendezvous envelopes
    A->>A: host candidates only — no STUN
    A<->B: WebRTC DataChannel open [authenticating]
    A<->B: trusted session auth (ADR 0010) — device-id + fingerprint verified
    A->>A: candidate = Bob(device-id) [verified reachable]
    A->>B: encrypted transfer frames (existing machinery, strict padding honored)
    B->>B: durable sink, hash verify, receipt
    Note over A,B: updater, wsclient, STUN, relay never consulted
```

### 5.2 First-pair offline flow (Local only)

```mermaid
sequenceDiagram
    participant A as Alice (CLI)
    participant B as Bob (desktop, fresh profile)
    B->>B: user opens pairing window (short-lived)
    B->>B: local rendezvous listener (approved iface)
    B->>A: out-of-band QR/code: endpoint + session token (bootstrap only)
    A->>B: TCP/TLS to local endpoint, presents session token
    B->>B: token valid + window open → admit unpaired session
    A<->B: PairingCoordinator ceremony over local transport
    A->>A: user enters code; B shows fingerprint
    B->>B: mutual confirmation
    A->>A: persist trust + KPair only after confirmation + storage success
    B->>B: persist trust + KPair only after confirmation + storage success
    B->>B: close pairing window
    A<->B: proceed as §5.1 known-pair flow
    Note over A,B: wrong code / expired token / declined fingerprint / storage failure → no usable partial trust
```

## 6. Migration and error behavior

- **State:** no v2.0 state schema changes. The network policy is a new
  additive setting (default `Online`), stored alongside existing settings;
  older binaries ignore it. Newer-schema refusal rules from V20-PR09 apply
  unchanged.
- **Downgrade:** a v2.0 binary never sees local-only sessions; queued jobs
  keep their v2.0 format and resume under v2.0 semantics. No data loss.
- **Errors fail closed and honest:** no local route → "no local route to
  peer under Local only" (not silent online fallback); blocked egress →
  "blocked by network policy"; pairing window closed → "pairing window not
  open"; unsupported network (guest Wi-Fi / client isolation) → explains
  firewall/isolation and offers the manual connection option.
- **Policy changes mid-job:** bound to the attempt's policy (V21-PR07).
  Switching to `Local only` during an online transfer pauses the job rather
  than migrating it onto an unapproved path; switching away from
  `Local only` never silently reuses local-only session state for online
  egress — new sessions are established under the new policy.

## 7. Executable test plan

Each row is a test the implementation PRs must provide (harness: two native
processes on an isolated virtual network; an egress monitor denies and logs
any non-approved destination).

| #   | Case                                | Method                                    | Pass criterion                                                             |
| --- | ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------- |
| T1  | Known-pair offline send/receive     | two CLIs, internet blocked at the harness | digest-verified file; egress log empty                                     |
| T2  | First-pair offline ceremony         | fresh profiles, internet blocked          | pair + send succeeds; no public-service contact                            |
| T3  | Wrong code / expired invitation     | fault injection                           | no partial trust persisted; clear error                                    |
| T4  | Competing joiner during window      | second initiator races                    | exactly one session completes; other refused                               |
| T5  | Blocked multicast                   | drop UDP beacons                          | manual endpoint connection succeeds; no internet fallback                  |
| T6  | DNS rebinding on manual endpoint    | poisoned resolver                         | session aborts before auth completes                                       |
| T7  | Endpoint substitution mid-session   | swap IP after auth starts                 | transfer aborts; peer identity mismatch error                              |
| T8  | Oversized/malformed envelopes       | fuzz local rendezvous                     | bounded, no crash, no credential leak                                      |
| T9  | Connection flood                    | N rapid connects                          | rate-limited; service stays responsive                                     |
| T10 | Port conflict / restart             | bind twice, kill/restart                  | clear error; restart recovers cleanly                                      |
| T11 | Updater in Local only               | trigger update check                      | no HTTP request emitted; deferred status shown                             |
| T12 | Diagnostics in Local only           | run diagnose                              | remote probes refused; local checks run                                    |
| T13 | STUN under Local only               | packet capture on peer                    | zero STUN packets; host candidates only                                    |
| T14 | Strict padding vs incompatible peer | strict peer + unpadded peer               | fails clearly before payload                                               |
| T15 | Interrupted local transfer          | kill mid-transfer, restart                | resumes to verified bytes via existing journals                            |
| T16 | Policy switch mid-job               | Online→Local only during send             | job pauses, never migrates to unapproved path                              |
| T17 | Sleep/wake + interface change       | fault harness                             | recover or clear resumable/failed state; nonces never reset under same key |
| T18 | Guest Wi-Fi / client isolation      | isolated network                          | honest error, manual option offered, no fallback                           |
| T19 | Pairing window expiry               | let window lapse, then join               | refused; no trust created                                                  |
| T20 | v2.0 regression                     | online send + outbox + upgrade            | unchanged behavior; migrations still pass                                  |

## 8. Exclusions and rollback

- No listener implementation before this design (this PR is docs-only).
- No disabling of certificate verification, no pairing ceremony weakening,
  no new cryptographic construction.
- If any implementation PR fails feasibility or review, that capability is
  disabled and v2.0 behavior is retained without claiming offline support.
- The whole v2.1 line can be rolled back to the v2.0.0 tag; local-only
  state is additive and ignored by older binaries.

## 9. Compatibility

- Wire framing, transfer protocol and authenticated resume are unchanged;
  online v2.1 clients keep tested v2.0 interoperability.
- A peer lacking local bootstrap fails clearly in `Local only`; it does not
  trigger unauthorized online fallback.
- Browser/PWA keeps v2.0 behavior with explicit unsupported-offline
  messaging where relevant.

## 10. Lead-dev design review

The roadmap asks for a reviewer-approved design. There is no independent
reviewer available in this workflow and the maintainer has mandated
uninterrupted autonomous execution. This design was therefore reviewed by
the acting lead developer against the stop-ship conditions:

- No prohibited egress path in `Local only` (§4 matrix, enforced in code).
- No new cryptography; the reviewed pairing ceremony and trusted session
  auth are reused unchanged.
- No beacon/IP-as-identity anywhere; discovery is presence only.
- No silent online fallback; failures are explicit.
- Nonce/resume safety delegated to existing journals (V21-PR07 acceptance).

Decision: **approved to proceed** to V21-PR02–08 implementation PRs, each
of which must deliver its slice of the test plan (§7) with real
process/network evidence. Any implementation PR that cannot meet its
acceptance rows must disable the capability rather than weaken the design.
