import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from './bytes.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import {
  buildRevocationChallenge,
  signRevocation,
  validateRevocationRecord,
  verifyRevocation,
  type RevocationRecord,
} from './revocation.js';

interface RevocationVector {
  name: string;
  revoker_seed_hex: string;
  revoker_device_id: string;
  revoker_pub_key_hex: string;
  revoked_device_id: string;
  seq: number;
  timestamp: string;
  challenge_hex: string;
  signature_hex: string;
  valid: boolean;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const vectorPath = path.resolve(__dirname, '../../wire/testdata/revocation-vectors.json');

describe('Revocation Records & Cross-Language Vectors', () => {
  const vectors: RevocationVector[] = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

  for (const v of vectors) {
    it(`Vector: ${v.name}`, async () => {
      const pubKey = hexToBytes(v.revoker_pub_key_hex);
      const rec: RevocationRecord = {
        revoker_device_id: v.revoker_device_id,
        revoked_device_id: v.revoked_device_id,
        seq: v.seq,
        timestamp: v.timestamp,
        signature: v.signature_hex,
      };

      const challenge = buildRevocationChallenge(
        v.revoker_device_id,
        v.revoked_device_id,
        v.seq,
        v.timestamp,
      );
      expect(bytesToHex(challenge)).toBe(v.challenge_hex);

      const now = new Date(v.timestamp);
      const ok = await verifyRevocation(rec, pubKey, 5 * 60 * 1000, now);
      expect(ok).toBe(v.valid);
    });
  }

  it('signs and verifies valid revocation records end-to-end', async () => {
    const seed = new Uint8Array(32).fill(7);
    const id = await createDeviceIdentityFromSeed(seed);
    const targetRevoked = 'sb-dev-1111111111111111111111111111111111111111111111111111111111111111';

    const now = new Date('2026-08-30T14:00:00Z');
    const rec = await signRevocation(id, targetRevoked, 1, now);

    expect(rec.revoker_device_id).toBe(id.deviceId);
    expect(rec.revoked_device_id).toBe(targetRevoked);
    expect(rec.seq).toBe(1);
    expect(rec.timestamp).toBe('2026-08-30T14:00:00.000Z');

    validateRevocationRecord(rec);

    const valid = await verifyRevocation(rec, id.publicKey, 5 * 60 * 1000, now);
    expect(valid).toBe(true);

    // Reject self-revocation
    await expect(signRevocation(id, id.deviceId, 1, now)).rejects.toThrow(
      'cannot revoke self in mesh sync',
    );

    // Reject tampered signature
    const tamperedSig: RevocationRecord = {
      ...rec,
      signature: bytesToHex(new Uint8Array(64).fill(0xee)),
    };
    expect(await verifyRevocation(tamperedSig, id.publicKey, 5 * 60 * 1000, now)).toBe(false);

    // Reject tampered payload
    const tamperedPayload: RevocationRecord = {
      ...rec,
      revoked_device_id: 'sb-dev-2222222222222222222222222222222222222222222222222222222222222222',
    };
    expect(await verifyRevocation(tamperedPayload, id.publicKey, 5 * 60 * 1000, now)).toBe(false);
  });
});
