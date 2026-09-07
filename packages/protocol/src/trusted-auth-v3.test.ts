import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from './bytes.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import {
  computeX25519SharedSecret,
  createTrustedAuthConfirmV3,
  createTrustedAuthInitV3,
  createTrustedAuthResponseV3,
  deriveTrustedSessionKeysV3,
  DOMAIN_TRUSTED_CONFIRM_INIT_3,
  DOMAIN_TRUSTED_CONFIRM_RESP_3,
  generateX25519KeyPair,
  NonceReplayCache,
  TRUSTED_AUTH_PROTOCOL_VERSION_V3,
  verifyTrustedAuthConfirmV3,
  verifyTrustedAuthInitV3,
  verifyTrustedAuthResponseV3,
  zeroizeBytes,
} from './trusted-auth.js';

interface TrustedV3Vector {
  name: string;
  protocol_version: string;
  k_pair_hex: string;
  pair_cred_ref: string;
  init_seed_hex: string;
  init_device_id: string;
  init_pub_key_hex: string;
  init_ephem_priv_hex: string;
  init_ephem_pub_hex: string;
  init_nonce_hex: string;
  init_caps: string[];
  init_timestamp: string;
  init_sig_hex: string;
  init_auth_tag_hex: string;
  resp_seed_hex: string;
  resp_device_id: string;
  resp_pub_key_hex: string;
  resp_ephem_priv_hex: string;
  resp_ephem_pub_hex: string;
  resp_nonce_hex: string;
  resp_caps: string[];
  resp_sig_hex: string;
  resp_auth_tag_hex: string;
  ecdh_shared_secret_hex: string;
  session_master_hex: string;
  i2r_key_hex: string;
  r2i_key_hex: string;
  init_confirm_tag: string;
  resp_confirm_tag: string;
}

describe('Trusted session V3 cross-language vector validation (sendbeam/3)', () => {
  const vectorPath = resolve(__dirname, '../../wire/testdata/trusted-session-v3-vectors.json');
  const vectorContent = readFileSync(vectorPath, 'utf-8');
  const vectors: TrustedV3Vector[] = JSON.parse(vectorContent);

  it('matches Go generated sendbeam/3 vectors byte-for-byte', async () => {
    for (const vec of vectors) {
      expect(vec.protocol_version).toBe(TRUSTED_AUTH_PROTOCOL_VERSION_V3);

      const kPair = hexToBytes(vec.k_pair_hex);
      const initSeed = hexToBytes(vec.init_seed_hex);
      const respSeed = hexToBytes(vec.resp_seed_hex);

      const idInit = await createDeviceIdentityFromSeed(initSeed);
      const idResp = await createDeviceIdentityFromSeed(respSeed);

      expect(idInit.deviceId).toBe(vec.init_device_id);
      expect(bytesToHex(idInit.publicKey)).toBe(vec.init_pub_key_hex);
      expect(idResp.deviceId).toBe(vec.resp_device_id);
      expect(bytesToHex(idResp.publicKey)).toBe(vec.resp_pub_key_hex);

      const initEphemPriv = hexToBytes(vec.init_ephem_priv_hex);
      const initEphemPub = hexToBytes(vec.init_ephem_pub_hex);
      const initNonce = hexToBytes(vec.init_nonce_hex);

      const respEphemPriv = hexToBytes(vec.resp_ephem_priv_hex);
      const respEphemPub = hexToBytes(vec.resp_ephem_pub_hex);
      const respNonce = hexToBytes(vec.resp_nonce_hex);

      // 1. Create TrustedAuthInitV3 and verify byte match
      const initMsg = await createTrustedAuthInitV3(
        idInit,
        idResp.deviceId,
        vec.pair_cred_ref,
        kPair,
        vec.init_caps,
        initEphemPub,
        initNonce,
        vec.init_timestamp,
      );

      expect(initMsg.protocol_version).toBe(TRUSTED_AUTH_PROTOCOL_VERSION_V3);
      expect(initMsg.signature).toBe(vec.init_sig_hex);
      expect(initMsg.auth_tag).toBe(vec.init_auth_tag_hex);

      // 2. Verify TrustedAuthInitV3 on responder
      const verInit = await verifyTrustedAuthInitV3(
        initMsg,
        kPair,
        idInit.publicKey,
        idResp.deviceId,
        vec.init_timestamp,
      );
      expect(bytesToHex(verInit.ephemeralPub)).toBe(vec.init_ephem_pub_hex);
      expect(bytesToHex(verInit.nonce)).toBe(vec.init_nonce_hex);

      // 3. Create TrustedAuthResponseV3 and verify byte match
      const respMsg = await createTrustedAuthResponseV3(
        idResp,
        initMsg,
        kPair,
        vec.resp_caps,
        respEphemPub,
        respNonce,
      );

      expect(respMsg.protocol_version).toBe(TRUSTED_AUTH_PROTOCOL_VERSION_V3);
      expect(respMsg.signature).toBe(vec.resp_sig_hex);
      expect(respMsg.auth_tag).toBe(vec.resp_auth_tag_hex);

      // 4. Verify TrustedAuthResponseV3 on initiator
      const verResp = await verifyTrustedAuthResponseV3(
        respMsg,
        initMsg,
        kPair,
        idResp.publicKey,
        idInit.deviceId,
      );
      expect(bytesToHex(verResp.ephemeralPub)).toBe(vec.resp_ephem_pub_hex);
      expect(bytesToHex(verResp.nonce)).toBe(vec.resp_nonce_hex);

      // 5. Diffie-Hellman shared secret
      const ssA = computeX25519SharedSecret(initEphemPriv, verResp.ephemeralPub);
      const ssB = computeX25519SharedSecret(respEphemPriv, verInit.ephemeralPub);
      expect(bytesToHex(ssA)).toBe(vec.ecdh_shared_secret_hex);
      expect(bytesToHex(ssB)).toBe(vec.ecdh_shared_secret_hex);

      // 6. Derive session keys
      const keysA = await deriveTrustedSessionKeysV3(
        kPair,
        ssA,
        initEphemPub,
        verResp.ephemeralPub,
        initNonce,
        verResp.nonce,
        idInit.deviceId,
        idResp.deviceId,
        vec.init_caps,
        respMsg.capabilities || [],
      );

      const keysB = await deriveTrustedSessionKeysV3(
        kPair,
        ssB,
        verInit.ephemeralPub,
        respEphemPub,
        verInit.nonce,
        respNonce,
        initMsg.initiator_device_id,
        idResp.deviceId,
        initMsg.capabilities,
        vec.resp_caps,
      );

      expect(bytesToHex(keysA.sessionMaster)).toBe(vec.session_master_hex);
      expect(bytesToHex(keysB.sessionMaster)).toBe(vec.session_master_hex);
      expect(bytesToHex(keysA.initiatorToResponderKey)).toBe(vec.i2r_key_hex);
      expect(bytesToHex(keysA.responderToInitiatorKey)).toBe(vec.r2i_key_hex);

      // 7. Confirmation handshake
      const confA = await createTrustedAuthConfirmV3(
        keysA.sessionMaster,
        DOMAIN_TRUSTED_CONFIRM_INIT_3,
        idInit.deviceId,
        true,
      );
      expect(confA.auth_tag).toBe(vec.init_confirm_tag);
      await expect(
        verifyTrustedAuthConfirmV3(
          confA,
          keysB.sessionMaster,
          DOMAIN_TRUSTED_CONFIRM_INIT_3,
          idInit.deviceId,
        ),
      ).resolves.toBeUndefined();

      const confB = await createTrustedAuthConfirmV3(
        keysB.sessionMaster,
        DOMAIN_TRUSTED_CONFIRM_RESP_3,
        idResp.deviceId,
        true,
      );
      expect(confB.auth_tag).toBe(vec.resp_confirm_tag);
      await expect(
        verifyTrustedAuthConfirmV3(
          confB,
          keysA.sessionMaster,
          DOMAIN_TRUSTED_CONFIRM_RESP_3,
          idResp.deviceId,
        ),
      ).resolves.toBeUndefined();

      // Zeroize test
      zeroizeBytes(ssA);
      zeroizeBytes(ssB);
      expect(ssA.every((b) => b === 0)).toBe(true);
      expect(ssB.every((b) => b === 0)).toBe(true);
    }
  });
});

describe('sendbeam/3 Downgrade rejection & security properties', () => {
  it('rejects sendbeam/2 or sendbeam/1 in verifyTrustedAuthInitV3', async () => {
    const seed = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111');
    const id = await createDeviceIdentityFromSeed(seed);
    const kp = generateX25519KeyPair();
    const kPair = new Uint8Array(32);
    const now = '2026-09-01T12:00:00Z';

    const initMsg = await createTrustedAuthInitV3(
      id,
      'sb-dev-responder',
      'cred-1',
      kPair,
      ['transfer.v2'],
      kp.publicKey,
      new Uint8Array(32),
      now,
    );

    // Tamper protocol version to sendbeam/2
    const initV2 = { ...initMsg, protocol_version: 'sendbeam/2' };
    await expect(
      verifyTrustedAuthInitV3(initV2, kPair, id.publicKey, 'sb-dev-responder', now),
    ).rejects.toThrow('trusted-session protocol downgrade forbidden');

    // Tamper protocol version to sendbeam/1
    const initV1 = { ...initMsg, protocol_version: 'sendbeam/1' };
    await expect(
      verifyTrustedAuthInitV3(initV1, kPair, id.publicKey, 'sb-dev-responder', now),
    ).rejects.toThrow('trusted-session protocol downgrade forbidden');
  });

  it('rejects sendbeam/2 or sendbeam/1 in verifyTrustedAuthResponseV3', async () => {
    const seed = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');
    const id = await createDeviceIdentityFromSeed(seed);
    const kp = generateX25519KeyPair();
    const kPair = new Uint8Array(32);
    const now = '2026-09-01T12:00:00Z';

    const initMsg = await createTrustedAuthInitV3(
      id,
      'sb-dev-resp',
      'cred-1',
      kPair,
      ['transfer.v2'],
      kp.publicKey,
      new Uint8Array(32),
      now,
    );

    const respV2 = {
      type: 'trusted_auth_response' as const,
      protocol_version: 'sendbeam/2',
      status: 'accepted' as const,
      responder_device_id: 'sb-dev-resp',
    };

    await expect(
      verifyTrustedAuthResponseV3(respV2, initMsg, kPair, new Uint8Array(32), id.deviceId),
    ).rejects.toThrow('trusted-session protocol downgrade forbidden');
  });

  it('detects weak and low-order X25519 ephemeral keys', () => {
    const kp = generateX25519KeyPair();

    // Invalid length
    expect(() => computeX25519SharedSecret(kp.secretKey, new Uint8Array(31))).toThrow(
      'ephemeral public key is weak or invalid',
    );
    expect(() => computeX25519SharedSecret(kp.secretKey, new Uint8Array(33))).toThrow(
      'ephemeral public key is weak or invalid',
    );

    // All-zero point
    expect(() => computeX25519SharedSecret(kp.secretKey, new Uint8Array(32))).toThrow(
      'ephemeral public key is weak or invalid',
    );

    // Point 1 (order 1)
    const pt1 = new Uint8Array(32);
    pt1[0] = 1;
    expect(() => computeX25519SharedSecret(kp.secretKey, pt1)).toThrow(
      'ephemeral public key is weak or invalid',
    );
  });

  it('detects session handshakes replayed within sliding-window cache', () => {
    const cache = new NonceReplayCache(5 * 60 * 1000);
    const devId = 'sb-dev-alice';
    const nonce = 'aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd';
    const now = 1700000000000;

    // First time succeeds
    expect(() => cache.checkAndRecord(devId, nonce, now)).not.toThrow();

    // Replay within TTL throws
    expect(() => cache.checkAndRecord(devId, nonce, now + 10000)).toThrow(
      'trusted-session replay detected',
    );

    // Different device succeeds
    expect(() => cache.checkAndRecord('sb-dev-bob', nonce, now)).not.toThrow();

    // Different nonce succeeds
    expect(() =>
      cache.checkAndRecord(
        devId,
        '112233445566778899aabbccdd00112233445566778899aabbccdd0011223344',
        now,
      ),
    ).not.toThrow();

    // After TTL expiry succeeds
    expect(() => cache.checkAndRecord(devId, nonce, now + 6 * 60 * 1000)).not.toThrow();
  });

  it('rejects adversarial tampering of timestamp, peer ID, signatures, and capabilities', async () => {
    const seedA = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');
    const seedB = hexToBytes('4444444444444444444444444444444444444444444444444444444444444444');
    const idA = await createDeviceIdentityFromSeed(seedA);
    const idB = await createDeviceIdentityFromSeed(seedB);
    const kpA = generateX25519KeyPair();
    const kpB = generateX25519KeyPair();
    const kPair = new Uint8Array(32);
    kPair.fill(0x77);

    const now = new Date('2026-09-01T12:00:00Z');
    const initMsg = await createTrustedAuthInitV3(
      idA,
      idB.deviceId,
      'cred-1',
      kPair,
      ['transfer.v2', 'mesh_sync'],
      kpA.publicKey,
      new Uint8Array(32),
      now,
    );

    // Clock skew > 5 minutes
    const expired = new Date(now.getTime() - 10 * 60 * 1000);
    await expect(
      verifyTrustedAuthInitV3(initMsg, kPair, idA.publicKey, idB.deviceId, expired),
    ).rejects.toThrow('trusted-session timestamp outside acceptable skew window');

    // Peer ID mismatch
    await expect(
      verifyTrustedAuthInitV3(initMsg, kPair, idA.publicKey, 'sb-dev-wrong', now),
    ).rejects.toThrow('trusted-session peer device ID mismatch');

    // Tampered signature
    const forgedSig = { ...initMsg, signature: bytesToHex(new Uint8Array(64)) };
    await expect(
      verifyTrustedAuthInitV3(forgedSig, kPair, idA.publicKey, idB.deviceId, now),
    ).rejects.toThrow('trusted-session signature verification failed');

    // Tampered MAC tag
    const forgedMAC = { ...initMsg, auth_tag: bytesToHex(new Uint8Array(32)) };
    await expect(
      verifyTrustedAuthInitV3(forgedMAC, kPair, idA.publicKey, idB.deviceId, now),
    ).rejects.toThrow('trusted-session MAC tag verification failed');

    // Tampered capabilities in init
    const tamperedCapsInit = { ...initMsg, capabilities: ['transfer.v2', 'injected_capability'] };
    await expect(
      verifyTrustedAuthInitV3(tamperedCapsInit, kPair, idA.publicKey, idB.deviceId, now),
    ).rejects.toThrow('trusted-session signature verification failed');

    // Tampered ephemeral public key
    const anotherKp = generateX25519KeyPair();
    const tamperedEphemInit = { ...initMsg, ephemeral_pub: bytesToHex(anotherKp.publicKey) };
    await expect(
      verifyTrustedAuthInitV3(tamperedEphemInit, kPair, idA.publicKey, idB.deviceId, now),
    ).rejects.toThrow('trusted-session signature verification failed');

    // Responder creates response, adversary tampers response capabilities
    const respMsg = await createTrustedAuthResponseV3(
      idB,
      initMsg,
      kPair,
      ['transfer.v2', 'mesh_sync'],
      kpB.publicKey,
      new Uint8Array(32),
    );

    const tamperedRespCaps = { ...respMsg, capabilities: ['transfer.v2'] };
    await expect(
      verifyTrustedAuthResponseV3(tamperedRespCaps, initMsg, kPair, idB.publicKey, idA.deviceId),
    ).rejects.toThrow('trusted-session signature verification failed');
  });
});
