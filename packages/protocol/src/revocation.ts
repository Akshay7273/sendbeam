/**
 * Cryptographically signed Revocation Records & mesh revocation sync.
 * Matches Go `packages/wire/revocation.go` byte-for-byte.
 */

import { bytesToHex, hexToBytes, utf8 } from './bytes.js';
import {
  type DeviceIdentity,
  deriveDeviceId,
  signDeviceMessage,
  validateDeviceId,
  verifyDeviceSignature,
} from './identity.js';

export const DOMAIN_REVOCATION_RECORD = 'sendbeam/2 revocation-record:';
export const MAX_REVOCATION_TIMESTAMP_SKEW_MS = 5 * 60 * 1000; // 5 minutes

export interface RevocationRecord {
  revoker_device_id: string;
  revoked_device_id: string;
  seq: number;
  timestamp: string; // RFC 3339 UTC format
  signature: string; // 128-char lowercase hex (64-byte Ed25519 signature)
}

/**
 * Build the canonical binary challenge for a revocation record.
 * Format: DomainRevocationRecord || RevokerDeviceID || RevokedDeviceID || BigEndian(Seq) || Timestamp
 */
export function buildRevocationChallenge(
  revokerId: string,
  revokedId: string,
  seq: number,
  timestamp: string,
): Uint8Array {
  const domainBytes = utf8(DOMAIN_REVOCATION_RECORD);
  const revokerBytes = utf8(revokerId);
  const revokedBytes = utf8(revokedId);

  const seqBytes = new Uint8Array(8);
  const view = new DataView(seqBytes.buffer);
  view.setBigUint64(0, BigInt(seq), false); // Big-endian

  const tsBytes = utf8(timestamp);

  const totalLen =
    domainBytes.length +
    revokerBytes.length +
    revokedBytes.length +
    seqBytes.length +
    tsBytes.length;
  const buf = new Uint8Array(totalLen);

  let offset = 0;
  buf.set(domainBytes, offset);
  offset += domainBytes.length;
  buf.set(revokerBytes, offset);
  offset += revokerBytes.length;
  buf.set(revokedBytes, offset);
  offset += revokedBytes.length;
  buf.set(seqBytes, offset);
  offset += seqBytes.length;
  buf.set(tsBytes, offset);

  return buf;
}

/**
 * Sign a new RevocationRecord using the local device's private identity key.
 */
export async function signRevocation(
  identity: DeviceIdentity,
  revokedDeviceId: string,
  seq: number,
  now = new Date(),
): Promise<RevocationRecord> {
  if (!identity) throw new Error('invalid identity: null or undefined');
  if (!validateDeviceId(revokedDeviceId)) {
    throw new Error(`invalid revoked device id: ${revokedDeviceId}`);
  }
  if (!Number.isInteger(seq) || seq <= 0) {
    throw new Error('seq must be a positive integer > 0');
  }

  const timestamp = now.toISOString();
  const challenge = buildRevocationChallenge(identity.deviceId, revokedDeviceId, seq, timestamp);
  const sigBytes = signDeviceMessage(identity, challenge);

  return {
    revoker_device_id: identity.deviceId,
    revoked_device_id: revokedDeviceId,
    seq,
    timestamp,
    signature: bytesToHex(sigBytes),
  };
}

/**
 * Sign a new self-tombstone RevocationRecord announcing this device's own revocation (ADR 0010 §4.2).
 */
export async function signSelfTombstone(
  identity: DeviceIdentity,
  seq: number,
  now = new Date(),
): Promise<RevocationRecord> {
  if (!identity) throw new Error('invalid identity: null or undefined');
  return signRevocation(identity, identity.deviceId, seq, now);
}

/**
 * Returns true if the revocation record is a self-tombstone where the revoker revokes itself (ADR 0010 §4.2).
 */
export function isSelfTombstone(record: RevocationRecord): boolean {
  return (
    !!record && !!record.revoker_device_id && record.revoker_device_id === record.revoked_device_id
  );
}

/**
 * Validate the structural integrity of a RevocationRecord.
 * Under ADR 0010 §4.2, self-tombstones (revoker_device_id === revoked_device_id) are structurally valid.
 */
export function validateRevocationRecord(record: RevocationRecord): void {
  if (!record) throw new Error('invalid revocation record: null or undefined');
  if (!validateDeviceId(record.revoker_device_id)) {
    throw new Error(`invalid revoker device id: ${record.revoker_device_id}`);
  }
  if (!validateDeviceId(record.revoked_device_id)) {
    throw new Error(`invalid revoked device id: ${record.revoked_device_id}`);
  }
  if (!Number.isInteger(record.seq) || record.seq <= 0) {
    throw new Error('seq must be a positive integer > 0');
  }
  if (!record.timestamp || isNaN(Date.parse(record.timestamp))) {
    throw new Error(`invalid timestamp: ${record.timestamp}`);
  }
  const sigBytes = hexToBytes(record.signature);
  if (sigBytes.length !== 64) {
    throw new Error('signature must be 64 bytes hex');
  }
}

/**
 * Verify a RevocationRecord against the revoker's public key and clock constraints.
 */
export async function verifyRevocation(
  record: RevocationRecord,
  revokerPublicKey: Uint8Array,
  maxSkewMs = MAX_REVOCATION_TIMESTAMP_SKEW_MS,
  now = new Date(),
): Promise<boolean> {
  try {
    validateRevocationRecord(record);
  } catch {
    return false;
  }

  const expectedRevokerId = await deriveDeviceId(revokerPublicKey);
  if (expectedRevokerId !== record.revoker_device_id) {
    return false;
  }

  const recordTime = Date.parse(record.timestamp);
  if (isNaN(recordTime)) return false;

  if (maxSkewMs > 0) {
    const skew = now.getTime() - recordTime;
    if (skew < -maxSkewMs) {
      // Timestamp is in the future beyond acceptable skew
      return false;
    }
  }

  const sigBytes = hexToBytes(record.signature);
  if (sigBytes.length !== 64) return false;

  const challenge = buildRevocationChallenge(
    record.revoker_device_id,
    record.revoked_device_id,
    record.seq,
    record.timestamp,
  );

  return verifyDeviceSignature(revokerPublicKey, challenge, sigBytes);
}

import {
  ERR_REVOCATION_SEQ_ROLLBACK,
  ERR_REVOCATION_UNAUTHORIZED,
  ERR_UNKNOWN_REVOKER,
} from './errors.js';
import type { TombstoneStore } from './tombstone-store.js';
import {
  RELATIONSHIP_CLUSTER_MEMBER,
  RELATIONSHIP_CLUSTER_OWNER,
  type TrustStore,
} from './trust-store.js';

export interface IngestRevocationOptions {
  tombstoneStore?: TombstoneStore;
  localClusterId?: string;
  localDeviceId?: string;
  localPublicKey?: Uint8Array;
  now?: Date;
  onAbortSession?: (deviceId: string) => void;
}

/**
 * Ingest and verify an incoming mesh RevocationRecord in accordance with ADR 0010 §4.4.
 */
export async function ingestRevocationRecord(
  record: RevocationRecord,
  trustStore: TrustStore,
  options?: IngestRevocationOptions,
): Promise<void> {
  // 1. Syntax validation
  validateRevocationRecord(record);

  const now = options?.now ?? new Date();
  const isSelf = record.revoker_device_id === record.revoked_device_id;
  const isLocal = Boolean(
    options?.localDeviceId && record.revoker_device_id === options.localDeviceId,
  );

  // 2. Retrieve Revoker A from local trust store
  let revokerPubBytes: Uint8Array;
  if (isLocal && options?.localPublicKey) {
    revokerPubBytes = options.localPublicKey;
  } else {
    const revoker = await trustStore.getDevice(record.revoker_device_id);
    if (!revoker) {
      if (isSelf) {
        if (options?.tombstoneStore) {
          await options.tombstoneStore.storeTombstone(record);
        }
        return;
      }
      throw new Error(ERR_UNKNOWN_REVOKER);
    }

    // 3. Check if Revoker A is already revoked locally
    if (revoker.revoked) {
      throw new Error('revocation revoker is revoked');
    }

    // 4. Authorization check
    if (!isSelf && !isLocal) {
      if (
        revoker.relationship !== RELATIONSHIP_CLUSTER_MEMBER &&
        revoker.relationship !== RELATIONSHIP_CLUSTER_OWNER
      ) {
        throw new Error(ERR_REVOCATION_UNAUTHORIZED);
      }
      if (!revoker.clusterId || revoker.clusterId.trim() === '') {
        throw new Error(ERR_REVOCATION_UNAUTHORIZED);
      }
      if (options?.localClusterId && revoker.clusterId !== options.localClusterId) {
        throw new Error(ERR_REVOCATION_UNAUTHORIZED);
      }
    }
    revokerPubBytes = hexToBytes(revoker.publicKey);
  }

  // 5. Retrieve Target B from local trust store
  const target = await trustStore.getDevice(record.revoked_device_id);
  if (!target) {
    if (options?.tombstoneStore) {
      await options.tombstoneStore.storeTombstone(record);
    }
    return;
  }

  // 6. Verify Ed25519 signature
  const sigValid = await verifyRevocation(
    record,
    revokerPubBytes,
    MAX_REVOCATION_TIMESTAMP_SKEW_MS,
    now,
  );
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  // 7. Sequence monotonicity check
  if (target.revoked && target.revocationSeq && record.seq <= target.revocationSeq) {
    throw new Error(ERR_REVOCATION_SEQ_ROLLBACK);
  }

  // 9. Apply revocation to Target B in trust store
  await trustStore.revokeDeviceWithRecord(record);

  if (options?.tombstoneStore) {
    await options.tombstoneStore.storeTombstone(record);
  }

  // 10. Abort active sessions
  options?.onAbortSession?.(record.revoked_device_id);
}
