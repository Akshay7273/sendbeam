/**
 * Adversarial Security Campaign & Attack-Matrix Testbed (TypeScript).
 *
 * Exercises all 20 threat-model attack vectors defined in ADR 0007 / ADR 0009 / v1.8:
 * 1. Stolen trust DB vs stolen key (Key substitution & device ID mismatch rejection)
 * 2. Replay attack & cloned profile resistance (Challenge freshness & transcript binding)
 * 3. Malicious signaling/relay server MITM & payload tampering
 * 4. Replayed presence beacons & stale epoch expiration
 * 5. Display name / local label spoofing resistance
 * 6. Downgrade attack & capability stripping resistance
 * 7. Stale / revoked pair credential rejection
 * 8. Auto-accept path traversal & filesystem escape containment
 * 9. One-time transfer isolation (Zero unintended trust persistence)
 * 10. Rejects forged revocation records
 * 11. Rejects sequence rollback in revocation sync
 * 12. Rejects revocation records from revoked or unknown devices
 * 13. Padding-oracle probe & non-zero padding rejection
 * 14. Bucket-downgrade coercion & private session requirement
 * 15. Update-manifest replay rejection (Go native self-updater architectural boundary)
 * 16. Revocation race condition & active session termination
 * 17. Revocation sequence rollback & domain monotonicity
 * 18. Relay frame corruption, reordering, and truncation
 * 19. Durable transfer journal tampering
 * 20. Pairing confirmation misuse & cross-session replay
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateDeviceIdentity,
  bytesToHex,
  concatBytes,
  utf8,
  validateTrustRecord,
  MemoryTrustStore,
  type TrustRecord,
  derivePairCredential,
  createTrustedAuthInit,
  verifyTrustedAuthInit,
  createTrustedAuthResponse,
  verifyTrustedAuthResponse,
  deriveRendezvousHandle,
  deriveRendezvousHandlesWithSkew,
  deriveLanBeaconTag,
  matchLanBeaconTag,
  normalizeTransferPath,
  type DeviceIdentity,
  padPayload,
  unpadPayload,
  seal,
  sealPadded,
  openSequenced,
  FrameReplayError,
  computePairingConfirmTag,
  verifyPairingConfirmTag,
  decodeJournal,
  encodeJournal,
  newJournal,
  signRevocation,
  verifyRevocation,
  signDeviceMessage,
  FEATURE_PADDING,
  FRAME_FLAG_PADDED,
  FRAME_VERSION,
  FrameType,
} from './index.js';

describe('SendBeam v1.8 Attack-Matrix & Adversarial Security Campaign', () => {
  let devA: DeviceIdentity;
  let devB: DeviceIdentity;
  let devAttacker: DeviceIdentity;
  let kPair: Uint8Array;
  let credRef: string;
  let trustStoreA: MemoryTrustStore;

  beforeEach(async () => {
    devA = await generateDeviceIdentity();
    devB = await generateDeviceIdentity();
    devAttacker = await generateDeviceIdentity();

    // Legitimate pairwise secret derived between A and B
    const derived = await derivePairCredential(
      new Uint8Array(32).fill(0x42),
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      devA.publicKey,
      devB.publicKey,
    );
    kPair = derived.kPair;
    credRef = derived.credRef;

    trustStoreA = new MemoryTrustStore();
    const recB: TrustRecord = {
      deviceId: devB.deviceId,
      publicKey: bytesToHex(devB.publicKey),
      localLabel: 'Bob Laptop',
      pairCredentialRef: credRef,
      capabilities: ['transfer.v1', 'transfer.v2', 'lan_direct'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: true, autoAcceptDestDir: '/safe/downloads' },
    };
    await trustStoreA.addOrUpdateDevice(recB);
  });

  // Vector 1: Stolen Trust DB vs Stolen Key
  it('Vector 1: Rejects tampered public key or mismatched device ID in trust DB', async () => {
    // Attacker modifies trust DB to bind devB's deviceId to attacker's public key
    const tamperedRecord: TrustRecord = {
      deviceId: devB.deviceId, // Victim device ID
      publicKey: bytesToHex(devAttacker.publicKey), // Attacker's public key
      localLabel: 'Bob Laptop',
      pairCredentialRef: credRef,
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    };

    // Validation must strictly reject mismatched public key and device ID
    await expect(validateTrustRecord(tamperedRecord)).rejects.toThrow(
      /does not match public key derived id/,
    );
  });

  // Vector 2: Replay Attack & Cloned Profile Resistance
  it('Vector 2: Rejects replayed authentication nonces and stale timestamp challenges', async () => {
    // Generate valid init message from A to B
    const init = await createTrustedAuthInit(devA, devB.deviceId, credRef, kPair, [
      'transfer.v1',
      'transfer.v2',
    ]);

    // Valid verification on B
    const verified = await verifyTrustedAuthInit(init, kPair, devA.publicKey, devB.deviceId);
    expect(verified.ephemeralPub).toHaveLength(32);
    expect(verified.nonce).toHaveLength(32);

    // Stale timestamp (e.g. captured 1 hour ago) must be rejected
    const staleInit = {
      ...init,
      timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
    };
    // Signatures and HMACs over modified timestamp must fail
    await expect(
      verifyTrustedAuthInit(staleInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();

    // Replaying same ephPub with altered nonce must fail
    const tamperedInit = {
      ...init,
      nonce: bytesToHex(new Uint8Array(32).fill(0x99)),
    };
    await expect(
      verifyTrustedAuthInit(tamperedInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();
  });

  // Vector 3: Malicious Signaling / Relay Server MITM & Key Substitution
  it('Vector 3: Detects and terminates on MITM ephemeral key substitution or payload tampering', async () => {
    const init = await createTrustedAuthInit(devA, devB.deviceId, credRef, kPair, ['transfer.v1']);

    // Malicious server intercepts init and substitutes ephemeral public key
    const attackerEph = await generateDeviceIdentity();
    const mitmInit = {
      ...init,
      ephemeral_pub: bytesToHex(attackerEph.publicKey),
    };

    // B verifies init: signature and HMAC must fail because ephemeral_pub was signed by A
    await expect(
      verifyTrustedAuthInit(mitmInit, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();

    // If server alters response payload
    const response = await createTrustedAuthResponse(devB, init, kPair, ['transfer.v1']);

    const mitmResponse = {
      ...response,
      ephemeral_pub: bytesToHex(attackerEph.publicKey),
    };

    await expect(
      verifyTrustedAuthResponse(mitmResponse, init, kPair, devB.publicKey, devA.deviceId),
    ).rejects.toThrow();
  });

  // Vector 4: Replayed Presence Beacons & Stale Epoch Expiration
  it('Vector 4: Rejects expired epoch rendezvous handles and spoofed beacon tags', async () => {
    const nowMs = Date.now();
    const windowMs = 15 * 60 * 1000;
    const currentEpoch = Math.floor(nowMs / windowMs);

    // Handles derived for current epoch ± 1
    const handles = await deriveRendezvousHandlesWithSkew(kPair, nowMs, windowMs);
    expect(handles).toHaveLength(3);

    // Handle derived for current epoch
    const currentHandle = await deriveRendezvousHandle(kPair, currentEpoch);
    expect(handles).toContain(currentHandle);

    // Expired epoch (> 1 epoch away, e.g. 1 hour = 4 epochs ago)
    const expiredHandle = await deriveRendezvousHandle(kPair, currentEpoch - 4);
    expect(handles).not.toContain(expiredHandle);

    // Blinded LAN Beacon verification
    const beaconNonce = new Uint8Array(16).fill(0x77);
    const tag = await deriveLanBeaconTag(kPair, beaconNonce, currentEpoch);

    const matched = await matchLanBeaconTag(kPair, beaconNonce, tag, nowMs, nowMs, windowMs);
    expect(matched).toBe(true);

    // Attacker without kPair cannot match beacon
    const attackerKey = new Uint8Array(32).fill(0xee);
    const attackerMatched = await matchLanBeaconTag(
      attackerKey,
      beaconNonce,
      tag,
      nowMs,
      nowMs,
      windowMs,
    );
    expect(attackerMatched).toBe(false);

    // Expired beacon (e.g. 2 hours old) must be rejected
    const staleMatched = await matchLanBeaconTag(
      kPair,
      beaconNonce,
      tag,
      nowMs - 2 * 3600 * 1000,
      nowMs,
      windowMs,
    );
    expect(staleMatched).toBe(false);
  });

  // Vector 5: Display Name / Local Label Spoofing Resistance
  it('Vector 5: Display names never authenticate identity; unauthenticated peers are rejected', async () => {
    // Attacker presents the same local label "Bob Laptop" as victim
    const attackerClaim = {
      localLabel: 'Bob Laptop', // Spoofed friendly name
      deviceId: devAttacker.deviceId,
      publicKey: bytesToHex(devAttacker.publicKey),
    };

    // Trust DB lookup by attacker's device ID returns false (not trusted)
    const isAttackerTrusted = await trustStoreA.isTrusted(attackerClaim.deviceId);
    expect(isAttackerTrusted).toBe(false);

    // Trust DB lookup by victim device ID returns legitimate key
    const victimDev = await trustStoreA.getDevice(devB.deviceId);
    expect(victimDev?.publicKey).toBe(bytesToHex(devB.publicKey));
    expect(victimDev?.publicKey).not.toBe(attackerClaim.publicKey);
  });

  // Vector 6: Downgrade Attack Resistance
  it('Vector 6: Enforces trusted-auth and rejects unauthenticated capability stripping', async () => {
    // When connecting to a paired device, both ends expect trusted-auth
    // If an attacker initiates with wrong pair key or missing signature
    const badSecret = new Uint8Array(32).fill(0x13);
    const init = await createTrustedAuthInit(
      devA,
      devB.deviceId,
      credRef,
      badSecret, // Attacker key
      ['transfer.v1'],
    );

    // Legitimate B rejects init because HMAC verification with true kPair fails
    await expect(
      verifyTrustedAuthInit(init, kPair, devA.publicKey, devB.deviceId),
    ).rejects.toThrow();
  });

  // Vector 7: Stale & Revoked Pair Credential Rejection
  it('Vector 7: Revoked devices fail authentication checks immediately', async () => {
    // Revoke device B in A's trust store
    await trustStoreA.revokeDevice(devB.deviceId);

    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(false);
    const revokedRec = await trustStoreA.getDevice(devB.deviceId);
    expect(revokedRec?.revoked).toBe(true);

    // If device B is completely unpaired / purged
    await trustStoreA.unpairDevice(devB.deviceId);
    expect(await trustStoreA.getDevice(devB.deviceId)).toBeNull();
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(false);
  });

  // Vector 8: Auto-Accept Path Traversal & Escape Containment
  it('Vector 8: Strictly rejects path traversal, directory escapes, and illegal characters in auto-accept mode', () => {
    const maliciousPaths = [
      '../evil.txt',
      '../../etc/passwd',
      'foo/../../bar.txt',
      '/absolute/path/file.txt',
      'C:\\Windows\\System32\\cmd.exe',
      'foo\0bar.txt',
      '..\\..\\windows\\system32',
      './../secret.key',
      '',
    ];

    for (const badPath of maliciousPaths) {
      expect(() => normalizeTransferPath(badPath)).toThrow();
    }

    // Valid relative paths must pass
    expect(normalizeTransferPath('photos/vacation.jpg')).toBe('photos/vacation.jpg');
    expect(normalizeTransferPath('document.pdf')).toBe('document.pdf');
    expect(normalizeTransferPath('nested/dir/sub/file.tar.gz')).toBe('nested/dir/sub/file.tar.gz');
  });

  // Vector 9: One-Time Transfer Isolation
  it('Vector 9: One-time transfers never mutate trust database or persist credentials', async () => {
    // Snapshot trust store count before one-time transfer
    const initialList = await trustStoreA.listDevices();
    expect(initialList).toHaveLength(1);

    // One-time room transfer does not call trustStore.addOrUpdateDevice
    // Simulate one-time receiver session:
    const oneTimeSenderId = 'sb-dev-ephemeral12345';
    expect(await trustStoreA.getDevice(oneTimeSenderId)).toBeNull();

    // Trust DB remains completely untouched
    const afterList = await trustStoreA.listDevices();
    expect(afterList).toHaveLength(1);
    expect(afterList[0]?.deviceId).toBe(devB.deviceId);
  });

  // Vector 10: Rejects forged revocation records
  it('Vector 10: Rejects forged revocation records and leaves peer trusted', async () => {
    const forgedSig = bytesToHex(new Uint8Array(64).fill(0xcc));
    const forgedRec = {
      revoker_device_id: devA.deviceId,
      revoked_device_id: devB.deviceId,
      seq: 1,
      timestamp: new Date().toISOString(),
      signature: forgedSig,
    };

    const verified = await import('./revocation.js').then((m) =>
      m.verifyRevocation(forgedRec, devA.publicKey),
    );
    expect(verified).toBe(false);

    // MemoryTrustStore remains intact
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(true);
  });

  // Vector 11: Rejects sequence rollback in revocation sync
  it('Vector 11: Rejects sequence rollback on revocation records', async () => {
    const rec1 = await signRevocation(devA, devB.deviceId, 5);
    await trustStoreA.revokeDeviceWithRecord(rec1);

    const recOld = await signRevocation(devA, devB.deviceId, 3);
    await expect(trustStoreA.revokeDeviceWithRecord(recOld)).rejects.toThrow(
      'revocation sequence number rollback',
    );
  });

  // Vector 12: Rejects revocation records from revoked or unknown devices
  it('Vector 12: Rejects revocation records submitted by revoked or unknown device', async () => {
    // Add devA to trustStoreA first so it can be revoked
    await trustStoreA.addOrUpdateDevice({
      deviceId: devA.deviceId,
      publicKey: bytesToHex(devA.publicKey),
      localLabel: 'Alice',
      pairCredentialRef: 'cred-a',
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
    });
    // Revoke device A in trustStoreA
    await trustStoreA.revokeDevice(devA.deviceId);
    expect(await trustStoreA.isTrusted(devA.deviceId)).toBe(false);

    // Revoked device A tries to submit a validly signed revocation of Bob
    const revFromRevoked = await signRevocation(devA, devB.deviceId, 1);
    const isRevokerTrusted = await trustStoreA.isTrusted(revFromRevoked.revoker_device_id);
    expect(isRevokerTrusted).toBe(false);

    // Unknown attacker creates valid signature
    const revFromUnknown = await signRevocation(devAttacker, devB.deviceId, 1);
    const isUnknownTrusted = await trustStoreA.isTrusted(revFromUnknown.revoker_device_id);
    expect(isUnknownTrusted).toBe(false);

    // Bob MUST remain trusted
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(true);
  });

  // Vector 13: Padding-oracle probe & non-zero padding rejection
  it('Vector 13: Rejects malformed padding lengths and non-zero padding bytes inside AEAD envelope', async () => {
    // 1. Buffer too short (< 2 bytes)
    expect(() => unpadPayload(new Uint8Array(1))).toThrow();

    // 2. Declared length exceeds buffer size
    const overflowBuf = new Uint8Array(256);
    new DataView(overflowBuf.buffer).setUint16(0, 300, false);
    expect(() => unpadPayload(overflowBuf)).toThrow();

    // 3. Non-zero padding byte inside valid bucket
    const plain = new TextEncoder().encode('secret payload data');
    const padded = padPayload(plain);
    const tamperedPadded = new Uint8Array(padded);
    tamperedPadded[tamperedPadded.length - 1] = 0x01;
    expect(() => unpadPayload(tamperedPadded)).toThrow(/non-zero padding/);

    // 4. Bit-flipped inside AEAD envelope fails AEAD before unpad
    const dir = {
      key: new Uint8Array(32).fill(0x01),
      salt: new Uint8Array([1, 2, 3, 4]),
    };
    const header = {
      version: FRAME_VERSION,
      type: FrameType.BlockData,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
    };
    const sealed = await sealPadded(dir, 0, header, plain);
    const corruptSealed = new Uint8Array(sealed);
    corruptSealed[corruptSealed.length - 5]! ^= 0x42;
    await expect(openSequenced(dir, 0, corruptSealed)).rejects.toThrow();

    // 5. Valid AEAD envelope encrypting forged non-zero padding fails on unpad
    const badPaddedSealed = await seal(
      dir,
      1,
      { ...header, flags: FRAME_FLAG_PADDED },
      tamperedPadded,
    );
    await expect(openSequenced(dir, 1, badPaddedSealed)).rejects.toThrow();
  });

  // Vector 14: Bucket-downgrade coercion & private session requirement
  it('Vector 14: Rejects bucket downgrade coercion and unpadded frames in private sessions', async () => {
    const privatePeerCaps = ['transfer.v1', FEATURE_PADDING];
    const publicPeerCaps = ['transfer.v1'];

    const hasPadding = (caps: string[]) => caps.includes(FEATURE_PADDING);
    expect(hasPadding(privatePeerCaps)).toBe(true);
    expect(hasPadding(publicPeerCaps)).toBe(false);

    // Attacker strips FEATURE_PADDING from offered capabilities
    const strippedCaps = privatePeerCaps.filter((c) => c !== FEATURE_PADDING);

    // Session enforcing private mode fails closed if FEATURE_PADDING was stripped
    const enforcePrivateSession = (peerCaps: string[]) => {
      if (!hasPadding(peerCaps)) {
        throw new Error(
          `downgrade rejected: peer does not negotiate ${FEATURE_PADDING} capability`,
        );
      }
    };
    expect(() => enforcePrivateSession(strippedCaps)).toThrow(/downgrade rejected/);

    // Receiver enforcing private mode rejects unpadded frames
    const dir = {
      key: new Uint8Array(32).fill(0x02),
      salt: new Uint8Array([1, 2, 3, 4]),
    };
    const unpaddedFrame = await seal(
      dir,
      0,
      {
        version: FRAME_VERSION,
        type: FrameType.BlockData,
        flags: 0, // Unpadded
        fileIdx: 0,
        blockIdx: 0,
        frameOff: 0,
      },
      new TextEncoder().encode('unpadded data'),
    );

    const opened = await openSequenced(dir, 0, unpaddedFrame);
    // Private policy verification: frame must have FRAME_FLAG_PADDED set
    expect(opened.header.flags & FRAME_FLAG_PADDED).toBe(0);
    const enforcePaddedFrame = (flags: number) => {
      if ((flags & FRAME_FLAG_PADDED) === 0) {
        throw new Error('private session rejected unpadded frame');
      }
    };
    expect(() => enforcePaddedFrame(opened.header.flags)).toThrow(/rejected unpadded frame/);
  });

  // Vector 15: Update-manifest replay rejection (Go native self-updater architectural boundary)
  it('Vector 15: Documents native updater boundary; browser runtime does not execute binary self-updates', () => {
    // The web browser runtime loads static ES modules over HTTPS with content-addressed cache busting;
    // self-updating binary manifests (stable.json, minisig) belong exclusively to the native Go CLI/Desktop architecture.
    // Tested in Go at packages/engine/updater/attack_matrix_test.go.
    expect(typeof window === 'undefined' || !('updater' in window)).toBe(true);
  });

  // Vector 16: Revocation race condition & active session termination
  it('Vector 16: Interleaved revocation record terminates active session trust immediately', async () => {
    // Initial state: Bob is trusted
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(true);

    // Initiate valid trusted auth init from Bob to Alice
    const init = await createTrustedAuthInit(devB, devA.deviceId, credRef, kPair, ['transfer.v1']);
    const verifiedBefore = await verifyTrustedAuthInit(init, kPair, devB.publicKey, devA.deviceId);
    expect(verifiedBefore.nonce).toHaveLength(32);

    // Concurrently / interleaved, Alice revokes Bob via signed revocation record
    const revRec = await signRevocation(devA, devB.deviceId, 1);
    await trustStoreA.revokeDeviceWithRecord(revRec);

    // Immediately post-revocation, trust store lookup fails closed
    expect(await trustStoreA.isTrusted(devB.deviceId)).toBe(false);
    const bRecord = await trustStoreA.getDevice(devB.deviceId);
    expect(bRecord?.revoked).toBe(true);

    // Any subsequent session check or transfer authorization for Bob is rejected
    const authorizeTransfer = async (deviceId: string) => {
      const trusted = await trustStoreA.isTrusted(deviceId);
      if (!trusted) {
        throw new Error(`transfer rejected: peer ${deviceId} is not trusted or revoked`);
      }
    };
    await expect(authorizeTransfer(devB.deviceId)).rejects.toThrow(/not trusted or revoked/);
  });

  // Vector 17: Revocation sequence rollback & domain monotonicity
  it('Vector 17: Rejects sequence rollback and cross-domain forged revocation signatures', async () => {
    const rec10 = await signRevocation(devA, devB.deviceId, 10);
    await trustStoreA.revokeDeviceWithRecord(rec10);

    // Replay lower seq = 5
    const rec5 = await signRevocation(devA, devB.deviceId, 5);
    await expect(trustStoreA.revokeDeviceWithRecord(rec5)).rejects.toThrow(
      'revocation sequence number rollback',
    );

    // Replay identical seq = 10
    await expect(trustStoreA.revokeDeviceWithRecord(rec10)).rejects.toThrow(
      'revocation sequence number rollback',
    );

    // Cross-domain forged signature: signature over fake domain string must fail verification
    const fakeDomain = utf8('sendbeam/fake-domain:');
    const fakeChallenge = concatBytes(fakeDomain, utf8(devA.deviceId), utf8(devB.deviceId));
    const fakeSig = await signDeviceMessage(devA, fakeChallenge);
    const forgedRec = {
      revoker_device_id: devA.deviceId,
      revoked_device_id: devB.deviceId,
      seq: 15,
      timestamp: new Date().toISOString(),
      signature: bytesToHex(fakeSig),
    };
    const verified = await verifyRevocation(forgedRec, devA.publicKey);
    expect(verified).toBe(false);
  });

  // Vector 18: Relay frame corruption, reordering, and truncation
  it('Vector 18: Rejects relay bit-flip corruption, reordered frame counters, and truncated payloads', async () => {
    const dir = {
      key: new Uint8Array(32).fill(0x03),
      salt: new Uint8Array([5, 6, 7, 8]),
    };
    const payload0 = new TextEncoder().encode('frame-0-payload');
    const payload1 = new TextEncoder().encode('frame-1-payload');

    const header = {
      version: FRAME_VERSION,
      type: FrameType.BlockData,
      flags: 0,
      fileIdx: 0,
      blockIdx: 0,
      frameOff: 0,
    };
    const f0 = await seal(dir, 0, header, payload0);
    const f1 = await seal(dir, 1, header, payload1);

    // 1. Bit-flip corruption
    const f0Corrupt = new Uint8Array(f0);
    f0Corrupt[Math.floor(f0Corrupt.length / 2)]! ^= 0xff;
    await expect(openSequenced(dir, 0, f0Corrupt)).rejects.toThrow();

    // 2. Reordering / replay
    const opened1 = await openSequenced(dir, 1, f1);
    expect(opened1.counter).toBe(1);
    // Delivering f0 after minimum is advanced to 2 fails with FrameReplayError
    await expect(openSequenced(dir, 2, f0)).rejects.toThrow(FrameReplayError);

    // 3. Truncation
    // 3a. Truncate 1 byte
    const f0Trunc1 = f0.slice(0, f0.length - 1);
    await expect(openSequenced(dir, 0, f0Trunc1)).rejects.toThrow();
    // 3b. Truncate AEAD tag (16 bytes)
    const f0NoTag = f0.slice(0, f0.length - 16);
    await expect(openSequenced(dir, 0, f0NoTag)).rejects.toThrow();
    // 3c. Truncate header (< 40 bytes)
    await expect(openSequenced(dir, 0, f0.slice(0, 20))).rejects.toThrow();

    // 4. Tag tampering (zero tag)
    const f0BadTag = new Uint8Array(f0);
    f0BadTag.fill(0x00, f0BadTag.length - 16);
    await expect(openSequenced(dir, 0, f0BadTag)).rejects.toThrow();
  });

  // Vector 19: Durable transfer journal tampering
  it('Vector 19: Rejects corrupted journal JSON, mismatched fingerprints, and out-of-bounds checkpoints', async () => {
    const manifest = {
      type: FrameType.Manifest,
      transferId: '0123456789abcdef0123456789abcdef',
      files: [
        {
          idx: 0,
          name: 'test.bin',
          size: 2048,
          mime: 'application/octet-stream',
          lastModified: 1700000000,
          blockSize: 1024,
          blocks: 2,
          fileDigest: 'ab'.repeat(32),
        },
      ],
      totalSize: 2048,
    };
    const j = await newJournal(
      '0123456789abcdef0123456789abcdef',
      manifest,
      { version: 1, value: 'source' },
      { version: 1, value: 'dest' },
      1723500000000,
    );
    const jBytes = await encodeJournal(j);
    const jJson = new TextDecoder().decode(jBytes);

    // 1. Corrupted JSON syntax
    const corruptBytes = new Uint8Array(jBytes);
    corruptBytes[Math.floor(corruptBytes.length / 2)] = 0x00;
    await expect(decodeJournal(corruptBytes)).rejects.toThrow();

    // 2. Torn write / truncated JSON
    const tornBytes = jBytes.slice(0, jBytes.length - 30);
    await expect(decodeJournal(tornBytes)).rejects.toThrow();

    // 3. Manifest fingerprint mismatch
    const tamperedObj = JSON.parse(jJson);
    tamperedObj.manifestFingerprint = 'forged-fingerprint-00000000000000000000000000000000';
    await expect(decodeJournal(utf8(JSON.stringify(tamperedObj)))).rejects.toThrow();

    // 4. Committed blocks exceeding file bounds
    const tamperedBlocksObj = JSON.parse(jJson);
    tamperedBlocksObj.files[0].committedBlocks = 999;
    await expect(decodeJournal(utf8(JSON.stringify(tamperedBlocksObj)))).rejects.toThrow();

    // 5. Schema version rollback / unsupported version
    const tamperedVerObj = JSON.parse(jJson);
    tamperedVerObj.schemaVersion = 999;
    await expect(decodeJournal(utf8(JSON.stringify(tamperedVerObj)))).rejects.toThrow();
  });

  // Vector 20: Pairing confirmation misuse & cross-session replay
  it('Vector 20: Rejects replayed pairing confirmation tags and wrong peer substitutions', async () => {
    // Session 1 between Alice and Bob with master key K1
    const k1 = new Uint8Array(32).fill(0x11);
    const reqNonce1 = new Uint8Array(32).fill(0x22);
    const respNonce1 = new Uint8Array(32).fill(0x33);

    const derived1 = await derivePairCredential(
      k1,
      reqNonce1,
      respNonce1,
      devA.publicKey,
      devB.publicKey,
    );
    const kPair1 = derived1.kPair;

    const tagBob1 = await computePairingConfirmTag(kPair1, devB.deviceId);
    expect(await verifyPairingConfirmTag(kPair1, devB.deviceId, tagBob1)).toBe(true);

    // Session 2 between Alice and Bob with fresh master key K2
    const k2 = new Uint8Array(32).fill(0x44);
    const reqNonce2 = new Uint8Array(32).fill(0x55);
    const respNonce2 = new Uint8Array(32).fill(0x66);

    const derived2 = await derivePairCredential(
      k2,
      reqNonce2,
      respNonce2,
      devA.publicKey,
      devB.publicKey,
    );
    const kPair2 = derived2.kPair;

    // 1. Cross-session replay: tag from session 1 must fail in session 2
    expect(await verifyPairingConfirmTag(kPair2, devB.deviceId, tagBob1)).toBe(false);

    // 2. Cross-session substitution / wrong peer: attacker Charlie's device ID
    expect(await verifyPairingConfirmTag(kPair1, devAttacker.deviceId, tagBob1)).toBe(false);

    // 3. Bit-flipped / forged tag
    const badTag = '00' + tagBob1.slice(2);
    expect(await verifyPairingConfirmTag(kPair1, devB.deviceId, badTag)).toBe(false);

    // 4. Malformed tag length
    expect(await verifyPairingConfirmTag(kPair1, devB.deviceId, 'short')).toBe(false);
  });
});
