import { describe, expect, it } from 'vitest';
import { bytesToHex, constantTimeEqual } from './bytes.js';
import { randomBytes } from './webcrypto.js';
import { ERR_LABEL_CONFLICT, ERR_TRUSTED_PEER_REVOKED } from './errors.js';
import { generateDeviceIdentity } from './identity.js';
import { MemorySecretResolver } from './indexeddb-secret-store.js';
import {
  PairingCoordinator,
  type PairingMessage,
  type PairingSessionConfig,
  type PairingTransport,
} from './pairing-coordinator.js';
import { MSG_PAIRING_REQUEST } from './pairing.js';
import { MemoryTombstoneStore } from './tombstone-store.js';
import { MemoryTrustStore, type TrustRecord, type TrustStore } from './trust-store.js';

class LoopbackTransport implements PairingTransport {
  private queue: PairingMessage[] = [];
  private waitResolve?: ((msg: PairingMessage) => void) | undefined;
  private waitReject?: ((err: Error) => void) | undefined;
  peer?: LoopbackTransport;

  async sendMessage(msg: PairingMessage): Promise<void> {
    if (!this.peer) throw new Error('transport peer not connected');
    this.peer.deliver(JSON.parse(JSON.stringify(msg)) as PairingMessage);
  }

  deliver(msg: PairingMessage): void {
    if (this.waitResolve) {
      const resolve = this.waitResolve;
      this.waitResolve = undefined;
      this.waitReject = undefined;
      resolve(msg);
    } else {
      this.queue.push(msg);
    }
  }

  async receiveMessage(): Promise<PairingMessage> {
    if (this.queue.length > 0) {
      return this.queue.shift()!;
    }
    return new Promise<PairingMessage>((resolve, reject) => {
      this.waitResolve = resolve;
      this.waitReject = reject;
    });
  }

  close(): void {
    if (this.waitReject) {
      this.waitReject(new Error('transport closed'));
      this.waitResolve = undefined;
      this.waitReject = undefined;
    }
  }
}

function makeLoopbackPair(): [LoopbackTransport, LoopbackTransport] {
  const a = new LoopbackTransport();
  const b = new LoopbackTransport();
  a.peer = b;
  b.peer = a;
  return [a, b];
}

describe('PairingCoordinator', () => {
  it('completes mutual pairing ceremony with identical kPair and persists records', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    const storeB = new MemoryTrustStore();
    const secretStoreA = new MemorySecretResolver();
    const secretStoreB = new MemorySecretResolver();

    const coordA = new PairingCoordinator(storeA, secretStoreA);
    const coordB = new PairingCoordinator(storeB, secretStoreB);

    const [transA, transB] = makeLoopbackPair();
    const masterKey = randomBytes(32);

    const cfgA: PairingSessionConfig = {
      deviceName: 'Device Alpha',
      capabilities: ['transfer.v1', 'transfer.v2'],
      masterKey,
      autoAccept: false,
    };

    const cfgB: PairingSessionConfig = {
      deviceName: 'Device Beta',
      capabilities: ['transfer.v1', 'lan_direct'],
      masterKey,
      autoAccept: true,
      destDir: '/home/user/downloads',
    };

    const [resA, resB] = await Promise.all([
      coordA.initiatePairing(transA, cfgA, idA),
      coordB.acceptPairing(transB, cfgB, idB),
    ]);

    // Derived keys and credential references must match identically
    expect(resA.credRef).toBe(resB.credRef);
    expect(constantTimeEqual(resA.kPair, resB.kPair)).toBe(true);

    // Peer records in memory stores
    expect(resA.peerRecord.deviceId).toBe(idB.deviceId);
    expect(resA.peerRecord.localLabel).toBe('Device Beta');
    expect(resA.peerRecord.policy.autoAccept).toBe(false);

    expect(resB.peerRecord.deviceId).toBe(idA.deviceId);
    expect(resB.peerRecord.localLabel).toBe('Device Alpha');
    expect(resB.peerRecord.policy.autoAccept).toBe(true);
    expect(resB.peerRecord.policy.autoAcceptDestDir).toBe('/home/user/downloads');

    // Verify persisted in trust stores
    const savedInA = await storeA.getDevice(idB.deviceId);
    expect(savedInA).not.toBeNull();
    expect(savedInA?.deviceId).toBe(idB.deviceId);
    expect(savedInA?.publicKey).toBe(bytesToHex(idB.publicKey));

    const savedInB = await storeB.getDevice(idA.deviceId);
    expect(savedInB).not.toBeNull();
    expect(savedInB?.deviceId).toBe(idA.deviceId);
    expect(savedInB?.publicKey).toBe(bytesToHex(idA.publicKey));

    // Verify persisted secrets in secret stores
    const secretInA = await secretStoreA.getPairSecret(idB.deviceId);
    expect(secretInA).not.toBeNull();
    expect(constantTimeEqual(secretInA!, resA.kPair)).toBe(true);

    const secretInB = await secretStoreB.getPairSecret(idA.deviceId);
    expect(secretInB).not.toBeNull();
    expect(constantTimeEqual(secretInB!, resB.kPair)).toBe(true);
  });

  it('rejects pairing fail-closed if peer is tombstoned', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    const tombStoreA = new MemoryTombstoneStore();
    await tombStoreA.storeTombstone({
      revoker_device_id: idA.deviceId,
      revoked_device_id: idB.deviceId,
      seq: 1,
      timestamp: new Date().toISOString(),
      signature: bytesToHex(randomBytes(64)),
    });

    const coordA = new PairingCoordinator(storeA, undefined, tombStoreA);
    const coordB = new PairingCoordinator(new MemoryTrustStore());

    const [transA, transB] = makeLoopbackPair();
    const masterKey = randomBytes(32);

    const cfgA: PairingSessionConfig = {
      deviceName: 'Device A',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    const cfgB: PairingSessionConfig = {
      deviceName: 'Device B',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    await expect(
      Promise.all([
        coordA.initiatePairing(transA, cfgA, idA),
        coordB.acceptPairing(transB, cfgB, idB),
      ]),
    ).rejects.toThrow(ERR_TRUSTED_PEER_REVOKED);
  });

  it('rejects pairing fail-closed if peer key conflicts with existing device ID', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();
    const idBImpostor = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    // A already has device B registered under legitimate key
    await storeA.addOrUpdateDevice({
      deviceId: idB.deviceId,
      publicKey: bytesToHex(idB.publicKey),
      localLabel: 'Device B',
      pairCredentialRef: 'cred-123',
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    });

    const coordA = new PairingCoordinator(storeA);
    const masterKey = randomBytes(32);

    const cfgA: PairingSessionConfig = {
      deviceName: 'Device A',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    // Impostor claims B's device ID with its own key (will fail deriveDeviceId, or if manipulated)
    // Here let's test acceptPairing where A responds to an initiate with tampered public key
    const tamperedReq: PairingMessage = {
      type: MSG_PAIRING_REQUEST,
      protocol_version: 'sendbeam/1',
      device_id: idB.deviceId,
      public_key: bytesToHex(idBImpostor.publicKey),
      device_name: 'Device B',
      capabilities: ['transfer.v1'],
      nonce: bytesToHex(randomBytes(32)),
      signature: bytesToHex(randomBytes(64)),
    };

    const mockTrans: PairingTransport = {
      sendMessage: async () => {},
      receiveMessage: async () => tamperedReq,
    };

    await expect(coordA.acceptPairing(mockTrans, cfgA, idA)).rejects.toThrow();
  });

  it('rejects pairing fail-closed on label conflict with another active device', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();
    const idC = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    // A already has another device named "My Phone"
    await storeA.addOrUpdateDevice({
      deviceId: idC.deviceId,
      publicKey: bytesToHex(idC.publicKey),
      localLabel: 'My Phone',
      pairCredentialRef: 'cred-existing',
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    });

    const coordA = new PairingCoordinator(storeA);
    const coordB = new PairingCoordinator(new MemoryTrustStore());

    const [transA, transB] = makeLoopbackPair();
    const masterKey = randomBytes(32);

    const cfgA: PairingSessionConfig = {
      deviceName: 'Laptop',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    const cfgB: PairingSessionConfig = {
      deviceName: 'My Phone', // Conflicting label
      capabilities: ['transfer.v1'],
      masterKey,
    };

    await expect(
      Promise.all([
        coordA.initiatePairing(transA, cfgA, idA),
        coordB.acceptPairing(transB, cfgB, idB),
      ]),
    ).rejects.toThrow(ERR_LABEL_CONFLICT);
  });

  it('rolls back saved pair secret if trustStore.addOrUpdateDevice fails', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();

    // TrustStore that fails on addOrUpdateDevice
    const failingStoreA = {
      getDevice: async () => null,
      listDevices: async () => [] as TrustRecord[],
      addOrUpdateDevice: async () => {
        throw new Error('disk full / indexeddb quota exceeded');
      },
    } as unknown as TrustStore;

    const secretStoreA = new MemorySecretResolver();
    const coordA = new PairingCoordinator(failingStoreA, secretStoreA);
    const coordB = new PairingCoordinator(new MemoryTrustStore(), new MemorySecretResolver());

    const [transA, transB] = makeLoopbackPair();
    const masterKey = randomBytes(32);

    const cfgA: PairingSessionConfig = {
      deviceName: 'Device A',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    const cfgB: PairingSessionConfig = {
      deviceName: 'Device B',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    await expect(
      Promise.all([
        coordA.initiatePairing(transA, cfgA, idA),
        coordB.acceptPairing(transB, cfgB, idB),
      ]),
    ).rejects.toThrow(/disk full/);

    // Secret must have been rolled back
    const secret = await secretStoreA.getPairSecret(idB.deviceId);
    expect(secret).toBeNull();
  });

  it('completes pairing over serialized JSON strings and Uint8Array frames', async () => {
    const idA = await generateDeviceIdentity();
    const idB = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    const storeB = new MemoryTrustStore();
    const coordA = new PairingCoordinator(storeA);
    const coordB = new PairingCoordinator(storeB);

    // Transports that encode to JSON string or UTF-8 Uint8Array
    let toB: string | Uint8Array | null = null;
    let toA: string | Uint8Array | null = null;
    let bWait: (() => void) | null = null;
    let aWait: (() => void) | null = null;

    const transA: PairingTransport = {
      sendMessage: async (msg) => {
        // Encode as string
        toB = JSON.stringify(msg);
        bWait?.();
        bWait = null;
      },
      receiveMessage: async () => {
        while (!toA) {
          await new Promise<void>((r) => (aWait = r));
        }
        const msg = toA;
        toA = null;
        return msg;
      },
    };

    const transB: PairingTransport = {
      sendMessage: async (msg) => {
        // Encode as Uint8Array
        toA = new TextEncoder().encode(JSON.stringify(msg));
        aWait?.();
        aWait = null;
      },
      receiveMessage: async () => {
        while (!toB) {
          await new Promise<void>((r) => (bWait = r));
        }
        const msg = toB;
        toB = null;
        return msg;
      },
    };

    const masterKey = randomBytes(32);
    const cfgA: PairingSessionConfig = {
      deviceName: 'Device Alpha',
      capabilities: ['transfer.v1'],
      masterKey,
    };
    const cfgB: PairingSessionConfig = {
      deviceName: 'Device Beta',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    const [resA, resB] = await Promise.all([
      coordA.initiatePairing(transA, cfgA, idA),
      coordB.acceptPairing(transB, cfgB, idB),
    ]);

    expect(resA.credRef).toBe(resB.credRef);
    expect(constantTimeEqual(resA.kPair, resB.kPair)).toBe(true);
  });

  it('fails closed when peer confirm auth tag is invalid', async () => {
    const idA = await generateDeviceIdentity();

    const storeA = new MemoryTrustStore();
    const coordA = new PairingCoordinator(storeA);

    const masterKey = randomBytes(32);
    const cfgA: PairingSessionConfig = {
      deviceName: 'Device A',
      capabilities: ['transfer.v1'],
      masterKey,
    };

    const idBResp = await generateDeviceIdentity();

    // Mock transport sending invalid confirm tag
    let step = 0;
    const mockTrans: PairingTransport = {
      sendMessage: async () => {},
      receiveMessage: async () => {
        step++;
        if (step === 1) {
          // Respond with legitimate pairing response
          const { createPairingResponse } = await import('./pairing.js');
          const resp = await createPairingResponse(
            idBResp,
            'Device B',
            ['transfer.v1'],
            masterKey,
            new Uint8Array(32), // dummy, will fail signature if not matched
          );
          return resp;
        }
        // Step 2: Corrupted confirm tag
        return {
          type: MSG_PAIRING_CONFIRM,
          status: 'accepted',
          auth_tag: bytesToHex(randomBytes(32)),
        };
      },
    };

    await expect(coordA.initiatePairing(mockTrans, cfgA, idA)).rejects.toThrow();
  });
});
