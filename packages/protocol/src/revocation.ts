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
  if (identity.deviceId === revokedDeviceId) {
    throw new Error('cannot revoke self in mesh sync');
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
 * Validate the structural integrity of a RevocationRecord.
 */
export function validateRevocationRecord(record: RevocationRecord): void {
  if (!record) throw new Error('invalid revocation record: null or undefined');
  if (!validateDeviceId(record.revoker_device_id)) {
    throw new Error(`invalid revoker device id: ${record.revoker_device_id}`);
  }
  if (!validateDeviceId(record.revoked_device_id)) {
    throw new Error(`invalid revoked device id: ${record.revoked_device_id}`);
  }
  if (record.revoker_device_id === record.revoked_device_id) {
    throw new Error('cannot revoke self in mesh sync');
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
