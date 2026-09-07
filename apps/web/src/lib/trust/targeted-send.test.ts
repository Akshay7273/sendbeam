import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  resolveTargetPeer,
  classifyBroadcastError,
  startTargetedSend,
  runBroadcastSend,
} from './targeted-send.js';
import { resetBrowserStoresForTesting } from './devices.js';
import {
  generateDeviceIdentity,
  bytesToHex,
  MemoryTrustStore,
  MemoryTombstoneStore,
  MemorySecretResolver,
  signRevocation,
} from '@sendbeam/protocol';
import type { TrustedDeviceUI } from './types.js';

// Mocks for rendezvous and transfer
const mocks = vi.hoisted(() => ({
  opaqueOffer: vi.fn(),
  runSend: vi.fn(),
}));

vi.mock('../session/opaque-rendezvous.js', () => ({
  opaqueOffer: mocks.opaqueOffer,
}));

vi.mock('../session/transfer.js', () => ({
  runSend: mocks.runSend,
}));

describe('Targeted Send & Multi-Send Engine', () => {
  let trustStore: MemoryTrustStore;
  let tombstoneStore: MemoryTombstoneStore;
  let secretStore: MemorySecretResolver;

  beforeEach(() => {
    vi.clearAllMocks();
    trustStore = new MemoryTrustStore();
    tombstoneStore = new MemoryTombstoneStore();
    secretStore = new MemorySecretResolver();
    resetBrowserStoresForTesting(trustStore, secretStore, tombstoneStore);
  });

  describe('resolveTargetPeer', () => {
    it('resolves active peer with derived handle and public key', async () => {
      const peerId = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(42);

      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Work Phone',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-1',
        capabilities: ['sendbeam/3', 'transfer.v1'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(peerId.deviceId, kPair);

      const resolved = await resolveTargetPeer(peerId.deviceId);
      expect(resolved.record.deviceId).toBe(peerId.deviceId);
      expect(resolved.kPair).toEqual(kPair);
      expect(resolved.peerPublicKey).toEqual(peerId.publicKey);
      expect(typeof resolved.handle).toBe('string');
      expect(resolved.handle).toHaveLength(64);
    });

    it('rejects unknown device', async () => {
      await expect(resolveTargetPeer('unknown-device')).rejects.toThrow(
        'Target device not found in trust store: unknown-device',
      );
    });

    it('rejects device marked revoked in trust store', async () => {
      const peerId = await generateDeviceIdentity();
      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Old Laptop',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-2',
        capabilities: ['transfer.v1'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: true,
        policy: { autoAccept: false },
      });

      await expect(resolveTargetPeer(peerId.deviceId)).rejects.toThrow(
        'Trust for device "Old Laptop" is revoked',
      );
    });

    it('rejects device revoked by tombstone', async () => {
      const peerId = await generateDeviceIdentity();
      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Compromised Tablet',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-3',
        capabilities: ['transfer.v1'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: false },
      });
      const localId = await generateDeviceIdentity();
      const rec = await signRevocation(localId, peerId.deviceId, 1);
      await tombstoneStore.storeTombstone(rec);

      await expect(resolveTargetPeer(peerId.deviceId)).rejects.toThrow(
        'Trust for device "Compromised Tablet" is revoked by tombstone',
      );
    });

    it('rejects device when pairing secret is missing', async () => {
      const peerId = await generateDeviceIdentity();
      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Forgotten Device',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-4',
        capabilities: ['transfer.v1'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: false },
      });

      await expect(resolveTargetPeer(peerId.deviceId)).rejects.toThrow(
        'Pairing secret missing for device "Forgotten Device"',
      );
    });
  });

  describe('classifyBroadcastError', () => {
    it('classifies refused/declined/canceled errors as refused', () => {
      expect(classifyBroadcastError(new Error('transfer declined by user')).status).toBe('refused');
      expect(classifyBroadcastError(new Error('transfer refused by user')).status).toBe('refused');
      expect(classifyBroadcastError(new Error('request rejected')).status).toBe('refused');
      expect(classifyBroadcastError(new Error('transfer cancelled')).status).toBe('refused');
      expect(classifyBroadcastError(new Error('trust revoked')).status).toBe('refused');
    });

    it('classifies network and timeout errors as offline', () => {
      expect(classifyBroadcastError(new Error('peer offline')).status).toBe('offline');
      expect(classifyBroadcastError(new Error('connection timeout')).status).toBe('offline');
      expect(classifyBroadcastError(new Error('signaling closed (1006)')).status).toBe('offline');
      expect(classifyBroadcastError(new Error('peer unreachable')).status).toBe('offline');
      expect(classifyBroadcastError(new Error('deadline exceeded')).status).toBe('offline');
    });

    it('classifies unknown and internal errors as failed', () => {
      expect(classifyBroadcastError(new Error('disk write error')).status).toBe('failed');
      expect(classifyBroadcastError(new Error('crypto auth failure')).status).toBe('failed');
      expect(classifyBroadcastError('arbitrary string error').status).toBe('failed');
    });
  });

  describe('startTargetedSend', () => {
    it('successfully connects and runs transfer', async () => {
      const peerId = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(7);

      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Target Device',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-send',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(peerId.deviceId, kPair);

      const fakeSignaling = { send: vi.fn(), close: vi.fn() };
      const fakeOutcome = {
        files: [{ name: 'test.txt', size: 12, sha256: 'abc' }],
        digest: 'sha256-abc',
        bytesTransferred: 12,
        durationMs: 50,
      };

      let transferDoneResolve!: (val: typeof fakeOutcome) => void;
      const transferDonePromise = new Promise<typeof fakeOutcome>((res) => {
        transferDoneResolve = res;
      });

      const fakeTransferCtrl = {
        progress: vi.fn(() => 12),
        done: transferDonePromise,
        cancel: vi.fn(),
      };

      mocks.opaqueOffer.mockReturnValue({
        handle: 'mock-handle',
        phase: 'connected',
        done: Promise.resolve({
          role: 'offerer',
          sessionKey: new Uint8Array(32),
          authKeys: { sign: new Uint8Array(32), verify: new Uint8Array(32) },
          remoteCaps: { version: 'sendbeam/3', maxFrame: 65536, blockSize: 65536, features: [] },
        }),
        adoptSignaling: vi.fn(() => fakeSignaling),
        cancel: vi.fn(),
      });

      mocks.runSend.mockReturnValue(fakeTransferCtrl);

      const states: string[] = [];
      const file = new File(['hello world!'], 'test.txt', { type: 'text/plain' });
      const targetUI: TrustedDeviceUI = {
        deviceId: peerId.deviceId,
        localLabel: 'Target Device',
        fingerprint: '1234 5678',
        publicKey: bytesToHex(peerId.publicKey),
        status: 'online',
        revoked: false,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['sendbeam/3'],
        policy: { autoAccept: true },
      };

      const session = await startTargetedSend({
        target: targetUI,
        files: [file],
        onStateChange: (st) => states.push(st),
      });

      expect(session.target).toBe(targetUI);
      expect(states).toContain('connecting');

      // Resolve transfer
      transferDoneResolve(fakeOutcome);
      const res = await session.done;

      expect(res).toEqual(fakeOutcome);
      expect(states).toContain('sending');
      expect(mocks.runSend).toHaveBeenCalledWith(
        expect.any(Object),
        fakeSignaling,
        expect.objectContaining({ files: [file] }),
      );
    });

    it('cancels rendezvous and transfer when cancel is invoked', async () => {
      const peerId = await generateDeviceIdentity();
      await trustStore.addOrUpdateDevice({
        deviceId: peerId.deviceId,
        localLabel: 'Cancel Target',
        publicKey: bytesToHex(peerId.publicKey),
        pairCredentialRef: 'cred-cancel',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(peerId.deviceId, new Uint8Array(32));

      const offerCancel = vi.fn();
      let resolveOffer!: (v: unknown) => void;
      const offerPromise = new Promise((res) => {
        resolveOffer = res;
      });

      mocks.opaqueOffer.mockReturnValue({
        handle: 'mock-handle',
        phase: 'connecting',
        done: offerPromise,
        adoptSignaling: vi.fn(),
        cancel: offerCancel,
      });

      const session = await startTargetedSend({
        target: {
          deviceId: peerId.deviceId,
          localLabel: 'Cancel Target',
          fingerprint: '1234',
          publicKey: bytesToHex(peerId.publicKey),
          status: 'online',
          revoked: false,
          lastSeenAt: new Date().toISOString(),
          firstSeenAt: new Date().toISOString(),
          capabilities: [],
          policy: { autoAccept: true },
        },
        files: [new File(['data'], 'test.txt')],
      });

      session.cancel('user aborted');
      expect(offerCancel).toHaveBeenCalledWith('user aborted');
      resolveOffer({});
      await expect(session.done).rejects.toThrow('transfer cancelled');
    });
  });

  describe('runBroadcastSend', () => {
    it('delivers to multiple targets with independent failure isolation', async () => {
      // Setup 3 peer devices:
      // Dev 1: succeeds
      // Dev 2: declined/refused
      // Dev 3: missing secret (fails resolution)
      const p1 = await generateDeviceIdentity();
      const p2 = await generateDeviceIdentity();
      const p3 = await generateDeviceIdentity();

      const kPair = new Uint8Array(32).fill(9);

      await trustStore.addOrUpdateDevice({
        deviceId: p1.deviceId,
        localLabel: 'Peer Success',
        publicKey: bytesToHex(p1.publicKey),
        pairCredentialRef: 'cred-1',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(p1.deviceId, kPair);

      await trustStore.addOrUpdateDevice({
        deviceId: p2.deviceId,
        localLabel: 'Peer Refuse',
        publicKey: bytesToHex(p2.publicKey),
        pairCredentialRef: 'cred-2',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(p2.deviceId, kPair);

      await trustStore.addOrUpdateDevice({
        deviceId: p3.deviceId,
        localLabel: 'Peer Missing Secret',
        publicKey: bytesToHex(p3.publicKey),
        pairCredentialRef: 'cred-3',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      // No secret for p3

      const targets: TrustedDeviceUI[] = [
        {
          deviceId: p1.deviceId,
          localLabel: 'Peer Success',
          fingerprint: '1111',
          publicKey: bytesToHex(p1.publicKey),
          status: 'online',
          revoked: false,
          lastSeenAt: '',
          firstSeenAt: '',
          capabilities: [],
          policy: { autoAccept: true },
        },
        {
          deviceId: p2.deviceId,
          localLabel: 'Peer Refuse',
          fingerprint: '2222',
          publicKey: bytesToHex(p2.publicKey),
          status: 'online',
          revoked: false,
          lastSeenAt: '',
          firstSeenAt: '',
          capabilities: [],
          policy: { autoAccept: true },
        },
        {
          deviceId: p3.deviceId,
          localLabel: 'Peer Missing Secret',
          fingerprint: '3333',
          publicKey: bytesToHex(p3.publicKey),
          status: 'online',
          revoked: false,
          lastSeenAt: '',
          firstSeenAt: '',
          capabilities: [],
          policy: { autoAccept: true },
        },
      ];

      mocks.opaqueOffer.mockImplementation((opts: { peerDeviceId: string }) => {
        if (opts.peerDeviceId === p1.deviceId) {
          return {
            done: Promise.resolve({ role: 'offerer' }),
            adoptSignaling: vi.fn(() => ({ send: vi.fn(), close: vi.fn() })),
            cancel: vi.fn(),
          };
        }
        if (opts.peerDeviceId === p2.deviceId) {
          return {
            done: Promise.reject(new Error('transfer declined by remote peer')),
            adoptSignaling: vi.fn(),
            cancel: vi.fn(),
          };
        }
        return {
          done: Promise.reject(new Error('unknown device')),
          adoptSignaling: vi.fn(),
          cancel: vi.fn(),
        };
      });

      mocks.runSend.mockReturnValue({
        progress: () => 100,
        done: Promise.resolve({ digest: 'sha256-verified' }),
        cancel: vi.fn(),
      });

      const files = [new File(['sample data'], 'file.txt')];
      const updates: Array<{ id: string; status: string }> = [];

      const result = await runBroadcastSend(targets, files, {
        concurrency: 2,
        onTargetUpdate: (s) => updates.push({ id: s.deviceId, status: s.status }),
      });

      expect(result.allOk).toBe(false);
      expect(result.results).toHaveLength(3);

      const res1 = result.results.find((r) => r.deviceId === p1.deviceId);
      expect(res1?.status).toBe('ok');
      expect(res1?.digest).toBe('sha256-verified');

      const res2 = result.results.find((r) => r.deviceId === p2.deviceId);
      expect(res2?.status).toBe('refused');
      expect(res2?.error).toContain('transfer declined by remote peer');

      const res3 = result.results.find((r) => r.deviceId === p3.deviceId);
      expect(res3?.status).toBe('failed');
      expect(res3?.error).toContain('Pairing secret missing');

      // CRITICAL: Ensure NO secrets or raw keys leak into output results
      for (const r of result.results) {
        const str = JSON.stringify(r);
        expect(str).not.toContain(bytesToHex(kPair));
        expect(str).not.toContain('kPair');
        expect(str).not.toContain('privateKey');
      }
    });

    it('returns allOk true when all targets succeed', async () => {
      const p1 = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(11);

      await trustStore.addOrUpdateDevice({
        deviceId: p1.deviceId,
        localLabel: 'Single Target',
        publicKey: bytesToHex(p1.publicKey),
        pairCredentialRef: 'cred-1',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(p1.deviceId, kPair);

      mocks.opaqueOffer.mockReturnValue({
        done: Promise.resolve({ role: 'offerer' }),
        adoptSignaling: vi.fn(() => ({ send: vi.fn(), close: vi.fn() })),
        cancel: vi.fn(),
      });

      mocks.runSend.mockReturnValue({
        progress: () => 50,
        done: Promise.resolve({ digest: 'digest-1' }),
        cancel: vi.fn(),
      });

      const targets: TrustedDeviceUI[] = [
        {
          deviceId: p1.deviceId,
          localLabel: 'Single Target',
          fingerprint: '1111',
          publicKey: bytesToHex(p1.publicKey),
          status: 'online',
          revoked: false,
          lastSeenAt: '',
          firstSeenAt: '',
          capabilities: [],
          policy: { autoAccept: true },
        },
      ];

      const result = await runBroadcastSend(targets, [new File(['x'], 'x.bin')]);
      expect(result.allOk).toBe(true);
      expect(result.results[0]?.status).toBe('ok');
      expect(result.results[0]?.digest).toBe('digest-1');
    });

    it('handles empty target list gracefully', async () => {
      const result = await runBroadcastSend([], []);
      expect(result.allOk).toBe(true);
      expect(result.results).toEqual([]);
    });
  });
});
