/**
 * Remote presence handles, opaque rendezvous discovery, and blinded LAN beacon tags (V15-PR04).
 *
 * Matches Go `packages/wire/presence.go` and `packages/wire/lan_beacon.go` byte-for-byte.
 */

import { bytesToHex, concatBytes, utf8 } from './bytes.js';
import { hmacSha256 } from './webcrypto.js';
import type { TrustStore } from './trust-store.js';
import type { SecretResolver } from './indexeddb-secret-store.js';

export const DOMAIN_RENDEZVOUS_HANDLE = 'sendbeam/2 rendezvous-handle:';
export const DOMAIN_PRESENCE_PROOF = 'sendbeam/2 presence-proof:';
export const DOMAIN_LAN_BEACON_TAG = 'sendbeam/2 lan-beacon:';

export const DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
export const LAN_BEACON_TAG_SIZE = 16;
export const LAN_BEACON_NONCE_SIZE = 16;

/**
 * Constant-time hex string comparison.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Derive a 32-byte opaque rendezvous handle for a specific epoch index.
 */
export async function deriveRendezvousHandle(
  kPair: Uint8Array,
  epochIndex: number | bigint,
): Promise<string> {
  const epochStr = epochIndex.toString();
  const data = concatBytes(utf8(DOMAIN_RENDEZVOUS_HANDLE), utf8(epochStr));
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Derive the opaque handle for a given timestamp and window.
 */
export async function deriveRendezvousHandleForTime(
  kPair: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<string> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return deriveRendezvousHandle(kPair, epochIndex);
}

/**
 * Derive current, previous, and next epoch handles to tolerate clock drift.
 */
export async function deriveRendezvousHandlesWithSkew(
  kPair: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<string[]> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return Promise.all([
    deriveRendezvousHandle(kPair, epochIndex - 1),
    deriveRendezvousHandle(kPair, epochIndex),
    deriveRendezvousHandle(kPair, epochIndex + 1),
  ]);
}

/**
 * Compute an HMAC proof of possession for registering or polling a handle.
 */
export async function derivePresenceProof(
  kPair: Uint8Array,
  handle: string,
  nonce: Uint8Array,
): Promise<string> {
  const data = concatBytes(utf8(DOMAIN_PRESENCE_PROOF), utf8(handle), nonce);
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Verify an HMAC proof of possession in constant time.
 */
export async function verifyPresenceProof(
  kPair: Uint8Array,
  handle: string,
  nonce: Uint8Array,
  proofHex: string,
): Promise<boolean> {
  const expected = await derivePresenceProof(kPair, handle, nonce);
  return constantTimeHexEqual(proofHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Derive a 16-byte truncated blinded tag for a paired device in a LAN beacon.
 */
export async function deriveLanBeaconTag(
  kPair: Uint8Array,
  nonce: Uint8Array,
  epochIndex: number | bigint,
): Promise<Uint8Array> {
  const epochStr = epochIndex.toString();
  const data = concatBytes(utf8(DOMAIN_LAN_BEACON_TAG), nonce, utf8(epochStr));
  const full = await hmacSha256(kPair, data);
  return full.slice(0, LAN_BEACON_TAG_SIZE);
}

/**
 * Compute candidate LAN beacon tags for [epoch-1, epoch, epoch+1].
 */
export async function deriveLanBeaconTagsForDevice(
  kPair: Uint8Array,
  nonce: Uint8Array,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<Uint8Array[]> {
  const timeMs = t instanceof Date ? t.getTime() : typeof t === 'number' ? t : Date.now();
  const epochIndex = Math.floor(timeMs / windowMs);
  return Promise.all([
    deriveLanBeaconTag(kPair, nonce, epochIndex - 1),
    deriveLanBeaconTag(kPair, nonce, epochIndex),
    deriveLanBeaconTag(kPair, nonce, epochIndex + 1),
  ]);
}

/**
 * Match a candidate beacon against known paired device secrets.
 */
export async function matchLanBeaconTag(
  kPair: Uint8Array,
  beaconNonce: Uint8Array,
  advertisedTag: Uint8Array,
  beaconTimestampMs: number,
  nowMs = Date.now(),
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<boolean> {
  const skew = Math.abs(nowMs - beaconTimestampMs);
  if (skew > 2 * windowMs) {
    return false;
  }
  const candidates = await deriveLanBeaconTagsForDevice(
    kPair,
    beaconNonce,
    beaconTimestampMs,
    windowMs,
  );
  const advHex = bytesToHex(advertisedTag);
  for (const cand of candidates) {
    if (constantTimeHexEqual(bytesToHex(cand), advHex)) {
      return true;
    }
  }
  return false;
}

/**
 * Validate that a handle is a 64-character lowercase hexadecimal string.
 */
export function validateRendezvousHandle(handle: string): boolean {
  if (typeof handle !== 'string' || handle.length !== 64) {
    return false;
  }
  for (let i = 0; i < handle.length; i++) {
    const c = handle.charCodeAt(i);
    if ((c < 48 || c > 57) && (c < 97 || c > 102)) {
      return false;
    }
  }
  return true;
}

/**
 * Check whether an advertised handle matches kPair candidate epochs.
 */
export async function matchRendezvousHandle(
  kPair: Uint8Array,
  handle: string,
  t?: Date | number,
  windowMs = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
): Promise<boolean> {
  if (!validateRendezvousHandle(handle)) {
    return false;
  }
  const candidates = await deriveRendezvousHandlesWithSkew(kPair, t, windowMs);
  for (const cand of candidates) {
    if (constantTimeHexEqual(cand, handle)) {
      return true;
    }
  }
  return false;
}

/**
 * Truthful presence states for paired peers.
 */
export type PresenceStatus = 'offline' | 'discovered' | 'connecting' | 'connected';

export interface PeerPresenceRecord {
  readonly deviceId: string;
  readonly status: PresenceStatus;
  readonly handle?: string | undefined;
  readonly lastSeenMs?: number | undefined;
  readonly expiresAtMs?: number | undefined;
}

/**
 * PresenceCoordinator manages opaque handle calculation, proof validation,
 * and truthful presence state transitions with epoch-bound expiry.
 */
export class PresenceCoordinator {
  private readonly records = new Map<string, PeerPresenceRecord>();

  constructor(
    private readonly trustStore: TrustStore,
    private readonly secretResolver: SecretResolver,
    private readonly epochWindowMs: number = DEFAULT_RENDEZVOUS_EPOCH_WINDOW_MS,
  ) {}

  /**
   * Returns active candidate handles for all non-revoked paired devices.
   */
  async getActiveHandles(nowMs: number = Date.now()): Promise<Map<string, string[]>> {
    const devices = await this.trustStore.listDevices();
    const result = new Map<string, string[]>();
    for (const dev of devices) {
      if (dev.revoked) continue;
      const kPair = await this.secretResolver.resolvePairSecret(
        dev.deviceId,
        dev.pairCredentialRef,
      );
      if (!kPair || kPair.length === 0) continue;
      const handles = await deriveRendezvousHandlesWithSkew(kPair, nowMs, this.epochWindowMs);
      result.set(dev.deviceId, handles);
    }
    return result;
  }

  /**
   * Matches an incoming handle and optional HMAC proof against known paired devices.
   */
  async matchInboundPresence(
    handle: string,
    nonce?: Uint8Array,
    proof?: string,
    nowMs: number = Date.now(),
  ): Promise<{ deviceId: string; verified: boolean } | null> {
    if (!validateRendezvousHandle(handle)) {
      return null;
    }
    const devices = await this.trustStore.listDevices();
    for (const dev of devices) {
      if (dev.revoked) continue;
      const kPair = await this.secretResolver.resolvePairSecret(
        dev.deviceId,
        dev.pairCredentialRef,
      );
      if (!kPair || kPair.length === 0) continue;

      if (await matchRendezvousHandle(kPair, handle, nowMs, this.epochWindowMs)) {
        if (proof && nonce && nonce.length > 0) {
          if (await verifyPresenceProof(kPair, handle, nonce, proof)) {
            this.recordPeerDiscovered(dev.deviceId, handle, nowMs);
            return { deviceId: dev.deviceId, verified: true };
          }
        } else {
          this.recordPeerDiscovered(dev.deviceId, handle, nowMs);
          return { deviceId: dev.deviceId, verified: true };
        }
      }
    }
    return null;
  }

  recordPeerDiscovered(deviceId: string, handle: string, nowMs: number = Date.now()): void {
    this.records.set(deviceId, {
      deviceId,
      status: 'discovered',
      handle,
      lastSeenMs: nowMs,
      expiresAtMs: nowMs + this.epochWindowMs,
    });
  }

  setPeerConnecting(deviceId: string): void {
    const existing = this.records.get(deviceId);
    this.records.set(deviceId, {
      deviceId,
      status: 'connecting',
      handle: existing?.handle,
      lastSeenMs: existing?.lastSeenMs ?? Date.now(),
      expiresAtMs: existing?.expiresAtMs,
    });
  }

  setPeerConnected(deviceId: string): void {
    const existing = this.records.get(deviceId);
    this.records.set(deviceId, {
      deviceId,
      status: 'connected',
      handle: existing?.handle,
      lastSeenMs: Date.now(),
    });
  }

  setPeerDisconnected(deviceId: string): void {
    const existing = this.records.get(deviceId);
    this.records.set(deviceId, {
      deviceId,
      status: 'offline',
      handle: existing?.handle,
      lastSeenMs: existing?.lastSeenMs,
    });
  }

  /**
   * Truthful presence query. If discovery epoch expired, returns 'offline'.
   */
  getPeerPresence(deviceId: string, nowMs: number = Date.now()): PresenceStatus {
    const rec = this.records.get(deviceId);
    if (!rec) return 'offline';
    if (rec.status === 'connected' || rec.status === 'connecting') {
      return rec.status;
    }
    if (rec.status === 'discovered') {
      if (rec.expiresAtMs && nowMs > rec.expiresAtMs) {
        // Truthful presence: discovery is ephemeral. Once epoch window expires, return offline!
        return 'offline';
      }
      return 'discovered';
    }
    return 'offline';
  }

  pruneExpired(nowMs: number = Date.now()): void {
    for (const [id, rec] of this.records.entries()) {
      if (rec.status === 'discovered' && rec.expiresAtMs && nowMs > rec.expiresAtMs) {
        this.records.set(id, {
          deviceId: id,
          status: 'offline',
          lastSeenMs: rec.lastSeenMs,
        });
      }
    }
  }
}
