# State Storage & Filesystem Locations

This document provides a comprehensive mapping of where SendBeam stores persistent state, configuration, transfer journals, sender records, and temporary files across Linux, macOS, Windows, and Web browsers.

---

## 1. Directory Overview by Operating System

| Platform    | Configuration Root (`ConfigDir`)                                          | Durable Data Root (`DataDir`)                                             |
| :---------- | :------------------------------------------------------------------------ | :------------------------------------------------------------------------ |
| **Linux**   | `$XDG_CONFIG_HOME/sendbeam`<br>(Default: `~/.config/sendbeam`)            | `$XDG_DATA_HOME/sendbeam`<br>(Default: `~/.local/share/sendbeam`)         |
| **macOS**   | `~/Library/Application Support/SendBeam`                                  | `~/Library/Application Support/SendBeam`                                  |
| **Windows** | `%APPDATA%\SendBeam`<br>(e.g. `C:\Users\<User>\AppData\Roaming\SendBeam`) | `%APPDATA%\SendBeam`<br>(e.g. `C:\Users\<User>\AppData\Roaming\SendBeam`) |
| **Web App** | IndexedDB (`sendbeam-state`)                                              | Origin Private File System (`OPFS`)                                       |

---

## 2. File & Directory Breakdown

### A. Desktop Configuration

- **File:** `config.json`
- **Location:** `<ConfigDir>/config.json`
- **Contents:** User settings (signaling server URL, close-to-tray preference, notifications toggle, STUN/TURN server URLs, and non-secret credential references).

### B. Single-Instance Lock

- **File:** `sendbeam.lock`
- **Location:** `<ConfigDir>/sendbeam.lock`
- **Purpose:** Acquired at application startup via OS file locking (`flock` on Unix, `LockFileEx` on Windows) to guarantee single-instance execution. Automatically released upon process termination.

### C. Durable Receive Journals (v1.3 Durable Resume)

- **Directory:** `.sendbeam/journals` (inside destination output directory)
- **Purpose:** Records block-granular verified progress, transfer ID, expected manifest fingerprint, and resume credentials for interrupted file downloads.
- **Cleanup:** Automatically purged upon verified file completion or explicitly via `sendbeam transfers discard <id>`.

### D. Sender Restart Records

- **Directory:** `<DataDir>/senders` (or `~/.sendbeam/senders`)
- **Purpose:** Stores local path key mappings to transfer IDs and resume secret envelopes so that re-sending the same files can resume an interrupted session without retransmitting already-committed blocks.

### E. Native Credentials & Keychains (v1.9 Trusted Handoffs)

SendBeam manages persistent device cryptographic identities and pairwise credentials (`k_pair`) with strict platform security boundaries:

- **Device Identity (`identity.key`):**
  - Stored at `<ConfigDir>/identity.key` with strict `0600` file permissions (`0700` directory).
  - Contains the Ed25519 private key seed.
  - **Fail-closed invariant:** If `identity.key` is zero-length, unparseable, or corrupted, SendBeam strictly refuses to overwrite or regenerate the identity. The error is raised immediately to prevent silent identity loss and unauthorized rotation.

- **Trust Store (`trust.json`):**
  - Stored at `<ConfigDir>/trust.json` (version 2 schema).
  - Maintains paired peer device records, public keys, display labels, capabilities, trust relationships (`contact`, `cluster_member`, `cluster_owner`), cluster IDs, and auto-accept transfer policies.
  - Migrated atomically and non-destructively from version 1 schema on startup.

- **OS-Protected Credential Stores (Desktop):**
  - **macOS:** Stored in macOS Keychain via `/usr/bin/security` under service `SendBeam` with account `sendbeam:pair:<deviceID>`.
  - **Windows:** Encrypted at rest scoped to the logged-in user via Windows DPAPI (`ProtectedData.Protect` with `CurrentUser` scope) in `<ConfigDir>/secrets/<hash>.dpapi`.
  - **Linux Desktop:** Stored in the freedesktop Secret Service keyring via `secret-tool` under service `SendBeam` with attribute `key=sendbeam:pair:<deviceID>`.
  - **No Plaintext Fallback:** The desktop runtime strictly refuses silent downgrade to plaintext files if the OS protected credential store is unavailable; operations fail closed with `ErrSecretStoreUnavailable`.
  - **Crash-Safe Legacy Migration:** On startup, if a legacy plaintext `secrets.json` file is detected, `MigrateLegacyFileSecrets` imports each secret into the protected store, verifies read-back integrity, zeroizes the plaintext file on disk, and renames it to `secrets.json.migrated`.

- **Headless / CLI Credential Storage (`FileSecretStore`):**
  - Headless environments without an active GUI session or OS secret service store credentials in `<ConfigDir>/secrets.json` with strict `0600` permissions.
  - **Explicit Limits:** Storage is restricted solely by POSIX file permissions to the executing user account. It does not provide hardware security module (HSM), TPM, or OS keychain protection. Users requiring hardware protection must run within an OS desktop session.

---

## 3. Web Client Storage Architecture

| Web Storage Primitive                 | Purpose                                                                                   | Lifetime                                                                                        |
| :------------------------------------ | :---------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------- |
| **IndexedDB** (`sendbeam_identity`)   | Stores local browser Ed25519 identity seed and public key.                                | Persistent until cleared. Corrupt seeds fail closed and strictly refuse overwrite/regeneration. |
| **IndexedDB** (`sendbeam_trust`)      | Stores paired peer device records, labels, trust relationships, and auto-accept policy.   | Persistent across sessions. Validated on load.                                                  |
| **IndexedDB** (`sendbeam_secrets`)    | Stores paired device pairwise secrets (`k_pair`).                                         | Persistent across sessions. Corrupt secrets fail closed and refuse parse.                       |
| **IndexedDB** (`sendbeam_journals`)   | Tracks transfer progress checkpoints, transfer lease IDs, and resume credentials.         | Persistent across page reloads and browser restarts until transfer completes or is discarded.   |
| **Origin Private File System (OPFS)** | Streams and stores incoming partial file chunks (`*.part`) with block-granular integrity. | Retained during interrupted transfers; finalized atomically to user download when complete.     |
| **SessionStorage / LocalStorage**     | Ephemeral UI states and theme preferences.                                                | Standard browser storage lifetime.                                                              |

### Explicit Browser Security Boundaries & Limits

- **Origin Boundary:** All browser keys, trust records, and pair secrets are restricted to the origin (`omnitrix.space` or `localhost`).
- **No Hardware Security Module / TPM:** In-browser cryptographic keys are maintained within browser IndexedDB storage and protected by browser sandbox boundaries, not OS Keychains or TPMs.
- **Private Browsing / Incognito:** Identities and pairings established in Private/Incognito windows are ephemeral and cleared on window close.
- **Fail-Closed on Corrupt Data:** If a stored identity seed in IndexedDB is malformed or invalid hex, the browser runtime strictly throws a descriptive error and refuses to generate a new key over the corrupt entry.

---

## 4. State Generations, Migrations, and Rollback (v2.0)

SendBeam versions its local state directory as a _generation_. Generation 2
is the v2.0 generation (durable jobs, outbox, transfer center).

- **Marker file:** `<ConfigDir>/state-version.json`
  (`{"version": 2, "updated_at": "..."}`), written atomically with `0600`
  permissions once all migrations succeed.
- **Startup migrations:** every CLI command runs the ordered migrations in
  `packages/engine/migrate` before any store is opened:
  1. `trust-store` — opens the file trust store, performing the atomic
     v1 → v2 schema upgrade on load when a v1.9 `trust.json` is found.
  2. `jobs-store` — bootstraps the v2.0 jobs directory and validates every
     existing job file.
- **Backup and rollback:** each migration snapshots the files it may touch
  before applying. If apply or verify fails, the snapshots are restored and
  the previous generation marker is left in place. Migrations never delete
  user state; a failed upgrade leaves the pre-upgrade state intact.
- **Newer-state quarantine:** if the marker records a generation newer than
  the running binary understands, startup refuses with an error and modifies
  nothing. Older binaries never truncate or reinterpret newer state.
- **Downgrade safety:** v1.x binaries ignore the unknown `state-version.json`
  marker and the v2.0-only `jobs/` directory, so rolling back the binary
  after a v2.0 upgrade loses no data. Dispatch rollback pauses work; the UI
  never deletes jobs on rollback.

First-run setup is available as `sendbeam onboard`, which runs the same
migration path, creates the device identity only when none exists, and
prints the device fingerprint plus next steps (`--json` for structured
output).

## 5. Managing and Clearing State

### CLI Transfers Command

```bash
# List all active or interrupted durable transfer journals:
sendbeam transfers list

# Inspect details of an interrupted transfer:
sendbeam transfers inspect <transfer-id>

# Resume an interrupted transfer:
sendbeam transfers resume <transfer-id> --code 7-guitarist-melody

# Discard an interrupted transfer and delete partial chunks:
sendbeam transfers discard <transfer-id>

# Discard all interrupted journals:
sendbeam transfers discard-all
```

### Complete Reset

To remove all local configuration and cached state:

- **Linux:** `rm -rf ~/.config/sendbeam ~/.local/share/sendbeam`
- **macOS:** `rm -rf ~/Library/Application\ Support/SendBeam`
- **Windows (PowerShell):** `Remove-Item -Recurse -Force "$env:APPDATA\SendBeam"`
- **Web App:** Clear site storage for `omnitrix.space` in browser developer tools.
