import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IncomingTransferCoordinator } from './incoming-listener.js';
import { resetBrowserStoresForTesting } from './devices.js';
import {
  generateDeviceIdentity,
  bytesToHex,
  MemoryTrustStore,
  MemoryTombstoneStore,
  MemorySecretResolver,
  signRevocation,
} from '@sendbeam/protocol';
import type { IncomingTransferRequest } from './types.js';

const mocks = vi.hoisted(() => ({
  opaqueJoin: vi.fn(),
  runReceive: vi.fn(),
}));

vi.mock('../session/opaque-rendezvous.js', () => ({
  opaqueJoin: mocks.opaqueJoin,
}));

vi.mock('../session/transfer.js', () => ({
  runReceive: mocks.runReceive,
}));

describe('IncomingTransferCoordinator', () => {
  let trustStore: MemoryTrustStore;
  let tombstoneStore: MemoryTombstoneStore;
  let secretStore: MemorySecretResolver;

  beforeEach(() => {
    vi.clearAllMocks();
    if (typeof window !== 'undefined') {
      delete (window as unknown as Record<string, unknown>).go;
      delete (window as unknown as Record<string, unknown>).runtime;
    }
    trustStore = new MemoryTrustStore();
    tombstoneStore = new MemoryTombstoneStore();
    secretStore = new MemorySecretResolver();
    resetBrowserStoresForTesting(trustStore, secretStore, tombstoneStore);
  });

  afterEach(() => {
    if (typeof window !== 'undefined') {
      delete (window as unknown as Record<string, unknown>).go;
      delete (window as unknown as Record<string, unknown>).runtime;
    }
  });

  describe('Desktop mode (Wails bridge)', () => {
    it('subscribes to sendbeam:consent and delegates decision to TransferService', async () => {
      let eventCallback: ((data: unknown) => void) | null = null;
      let cleanupCalled = false;
      let respondCalledWith: [string, unknown] | null = null;

      globalThis.window = {
        go: {
          engine: {
            DeviceService: {},
            TransferService: {
              RespondConsent: async (id: string, decision: unknown) => {
                respondCalledWith = [id, decision];
              },
            },
          },
        },
        runtime: {
          EventsOn: (evt: string, cb: (data: unknown) => void) => {
            if (evt === 'sendbeam:consent') {
              eventCallback = cb;
            }
            return () => {
              cleanupCalled = true;
            };
          },
        },
      } as unknown as Window & typeof globalThis;

      let incomingReq: IncomingTransferRequest | null = null;
      const coordinator = new IncomingTransferCoordinator({
        onIncomingRequest: (req) => {
          incomingReq = req;
        },
      });

      await coordinator.start();
      expect(eventCallback).toBeDefined();

      // Trigger incoming consent event from native desktop engine
      eventCallback!({
        transferId: 'tx-desktop-1',
        peerDeviceId: 'sb-dev-desktop-peer',
        peerLabel: 'MacBook Studio',
        files: [{ name: 'presentation.key', size: 1024 * 1024 }],
        totalSize: 1024 * 1024,
      });

      const req = incomingReq as IncomingTransferRequest | null;
      expect(req).not.toBeNull();
      expect(req?.transferId).toBe('tx-desktop-1');
      expect(req?.senderLabel).toBe('MacBook Studio');
      expect(req?.fileCount).toBe(1);
      expect(req?.totalBytes).toBe(1024 * 1024);

      // Respond accept
      await coordinator.respondConsent('tx-desktop-1', true);
      expect(respondCalledWith).toEqual(['tx-desktop-1', { accepted: true }]);

      // Respond decline
      await coordinator.respondConsent('tx-desktop-1', false, 'user declined');
      expect(respondCalledWith).toEqual([
        'tx-desktop-1',
        { accepted: false, reason: 'user declined' },
      ]);

      // Stop coordinator
      coordinator.stop();
      expect(cleanupCalled).toBe(true);
    });
  });

  describe('Browser mode (Opaque Rendezvous)', () => {
    it('spawns listeners for active devices and ignores revoked or missing secrets', async () => {
      const activePeer = await generateDeviceIdentity();
      const revokedPeer = await generateDeviceIdentity();
      const tombstonedPeer = await generateDeviceIdentity();
      const noSecretPeer = await generateDeviceIdentity();

      const kPair = new Uint8Array(32).fill(12);

      // 1. Active device
      await trustStore.addOrUpdateDevice({
        deviceId: activePeer.deviceId,
        localLabel: 'Active Phone',
        publicKey: bytesToHex(activePeer.publicKey),
        pairCredentialRef: 'cred-1',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(activePeer.deviceId, kPair);

      // 2. Revoked device in trust store
      await trustStore.addOrUpdateDevice({
        deviceId: revokedPeer.deviceId,
        localLabel: 'Revoked Phone',
        publicKey: bytesToHex(revokedPeer.publicKey),
        pairCredentialRef: 'cred-2',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: true,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(revokedPeer.deviceId, kPair);

      // 3. Tombstoned device
      await trustStore.addOrUpdateDevice({
        deviceId: tombstonedPeer.deviceId,
        localLabel: 'Tombstoned Tablet',
        publicKey: bytesToHex(tombstonedPeer.publicKey),
        pairCredentialRef: 'cred-3',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });
      await secretStore.setPairSecret(tombstonedPeer.deviceId, kPair);
      const rec = await signRevocation(activePeer, tombstonedPeer.deviceId, 1);
      await tombstoneStore.storeTombstone(rec);

      // 4. Device without pair secret
      await trustStore.addOrUpdateDevice({
        deviceId: noSecretPeer.deviceId,
        localLabel: 'No Secret Peer',
        publicKey: bytesToHex(noSecretPeer.publicKey),
        pairCredentialRef: 'cred-4',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true },
      });

      const cancelFn = vi.fn();
      mocks.opaqueJoin.mockReturnValue({
        handle: 'h1',
        phase: 'listening',
        done: new Promise(() => {}), // keeps listening
        adoptSignaling: vi.fn(),
        cancel: cancelFn,
      });

      const coordinator = new IncomingTransferCoordinator();
      await coordinator.start();

      // Only activePeer should have an opaqueJoin listener spawned
      expect(mocks.opaqueJoin).toHaveBeenCalledTimes(1);
      expect(mocks.opaqueJoin).toHaveBeenCalledWith(
        expect.objectContaining({
          peerDeviceId: activePeer.deviceId,
          kPair,
        }),
      );

      coordinator.stop();
      expect(cancelFn).toHaveBeenCalledWith('listener stopped');
    });

    it('handles auto-accept transfers without prompting user', async () => {
      const peer = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(15);

      await trustStore.addOrUpdateDevice({
        deviceId: peer.deviceId,
        localLabel: 'Auto Accept Laptop',
        publicKey: bytesToHex(peer.publicKey),
        pairCredentialRef: 'cred-auto',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: true }, // AUTO ACCEPT = TRUE
      });
      await secretStore.setPairSecret(peer.deviceId, kPair);

      let resolveJoin!: (res: unknown) => void;
      const joinDone = new Promise((res) => {
        resolveJoin = res;
      });

      const fakeSignaling = { send: vi.fn(), close: vi.fn() };
      mocks.opaqueJoin.mockReturnValue({
        handle: 'h-auto',
        phase: 'listening',
        done: joinDone,
        adoptSignaling: vi.fn(() => fakeSignaling),
        cancel: vi.fn(),
      });

      const expectedOutcome = {
        files: [{ name: 'auto.pdf', size: 50, sha256: 'xyz' }],
        digest: 'sha256-xyz',
        bytesTransferred: 50,
        durationMs: 20,
      };

      let consentCallback:
        | ((manifest: {
            files: Array<{ name: string; size: number }>;
            totalSize: number;
          }) => Promise<boolean>)
        | undefined;

      mocks.runReceive.mockImplementation((_rendezvous, _signaling, _dest, opts) => {
        consentCallback = opts?.onConsent;
        return {
          progress: () => 50,
          done: Promise.resolve(expectedOutcome),
          cancel: vi.fn(),
        };
      });

      let promptCalled = false;
      let transferStarted = false;
      let completedOutcome: unknown = null;

      const coordinator = new IncomingTransferCoordinator({
        onIncomingRequest: () => {
          promptCalled = true;
        },
        onTransferStart: () => {
          transferStarted = true;
        },
        onTransferComplete: (_id, out) => {
          completedOutcome = out;
        },
      });

      await coordinator.start();

      // Resolve rendezvous handshake
      resolveJoin({
        role: 'joiner',
        sessionKey: new Uint8Array(32),
        authKeys: { sign: new Uint8Array(32), verify: new Uint8Array(32) },
      });

      // Allow microtasks to settle
      await Promise.resolve();
      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 10));

      expect(mocks.runReceive).toHaveBeenCalled();
      expect(consentCallback).toBeDefined();

      // Trigger consent hook: should return true automatically without user prompt
      const consentResult = await consentCallback!({
        files: [{ name: 'auto.pdf', size: 50 }],
        totalSize: 50,
      });

      expect(consentResult).toBe(true);
      expect(promptCalled).toBe(false);

      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 10));

      expect(transferStarted).toBe(true);
      expect(completedOutcome).toEqual(expectedOutcome);

      coordinator.stop();
    });

    it('prompts user and handles consent acceptance', async () => {
      const peer = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(21);

      await trustStore.addOrUpdateDevice({
        deviceId: peer.deviceId,
        localLabel: 'Manual Accept Laptop',
        publicKey: bytesToHex(peer.publicKey),
        pairCredentialRef: 'cred-manual',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: false }, // AUTO ACCEPT = FALSE
      });
      await secretStore.setPairSecret(peer.deviceId, kPair);

      let resolveJoin!: (res: unknown) => void;
      const joinDone = new Promise((res) => {
        resolveJoin = res;
      });

      mocks.opaqueJoin.mockReturnValue({
        handle: 'h-manual',
        phase: 'listening',
        done: joinDone,
        adoptSignaling: vi.fn(() => ({ send: vi.fn(), close: vi.fn() })),
        cancel: vi.fn(),
      });

      let consentCallback:
        | ((manifest: {
            files: Array<{ name: string; size: number }>;
            totalSize: number;
          }) => Promise<boolean>)
        | undefined;

      mocks.runReceive.mockImplementation((_rendezvous, _signaling, _dest, opts) => {
        consentCallback = opts?.onConsent;
        return {
          progress: () => 100,
          done: Promise.resolve({ digest: 'digest-manual' }),
          cancel: vi.fn(),
        };
      });

      let incomingRequest: IncomingTransferRequest | null = null;

      const coordinator = new IncomingTransferCoordinator({
        onIncomingRequest: (req) => {
          incomingRequest = req;
        },
      });

      await coordinator.start();

      resolveJoin({
        role: 'joiner',
        sessionKey: new Uint8Array(32),
        authKeys: { sign: new Uint8Array(32), verify: new Uint8Array(32) },
      });

      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 10));

      expect(consentCallback).toBeDefined();

      // Start consent inquiry
      const consentPromise = consentCallback!({
        files: [{ name: 'manual.pdf', size: 100 }],
        totalSize: 100,
      });

      await Promise.resolve();
      const manualReq = incomingRequest as IncomingTransferRequest | null;
      expect(manualReq).not.toBeNull();
      expect(manualReq?.senderLabel).toBe('Manual Accept Laptop');
      expect(manualReq?.fileCount).toBe(1);

      // Accept consent
      await coordinator.respondConsent(manualReq!.transferId, true);

      const decision = await consentPromise;
      expect(decision).toBe(true);

      coordinator.stop();
    });

    it('prompts user and handles consent decline', async () => {
      const peer = await generateDeviceIdentity();
      const kPair = new Uint8Array(32).fill(25);

      await trustStore.addOrUpdateDevice({
        deviceId: peer.deviceId,
        localLabel: 'Decline Laptop',
        publicKey: bytesToHex(peer.publicKey),
        pairCredentialRef: 'cred-decline',
        capabilities: ['sendbeam/3'],
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revoked: false,
        policy: { autoAccept: false },
      });
      await secretStore.setPairSecret(peer.deviceId, kPair);

      let resolveJoin!: (res: unknown) => void;
      const joinDone = new Promise((res) => {
        resolveJoin = res;
      });

      mocks.opaqueJoin.mockReturnValue({
        handle: 'h-decline',
        phase: 'listening',
        done: joinDone,
        adoptSignaling: vi.fn(() => ({ send: vi.fn(), close: vi.fn() })),
        cancel: vi.fn(),
      });

      let consentCallback:
        | ((manifest: {
            files: Array<{ name: string; size: number }>;
            totalSize: number;
          }) => Promise<boolean>)
        | undefined;

      mocks.runReceive.mockImplementation((_rendezvous, _signaling, _dest, opts) => {
        consentCallback = opts?.onConsent;
        return {
          progress: () => 0,
          done: Promise.reject(new Error('transfer declined by user')),
          cancel: vi.fn(),
        };
      });

      let incomingRequest: IncomingTransferRequest | null = null;
      let reportedError: Error | null = null;

      const coordinator = new IncomingTransferCoordinator({
        onIncomingRequest: (req) => {
          incomingRequest = req;
        },
        onTransferError: (_id, err) => {
          reportedError = err;
        },
      });

      await coordinator.start();

      resolveJoin({
        role: 'joiner',
        sessionKey: new Uint8Array(32),
        authKeys: { sign: new Uint8Array(32), verify: new Uint8Array(32) },
      });

      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 10));

      const consentPromise = consentCallback!({
        files: [{ name: 'decline.pdf', size: 200 }],
        totalSize: 200,
      });

      await Promise.resolve();
      const declineReq = incomingRequest as IncomingTransferRequest | null;
      expect(declineReq).not.toBeNull();

      // Decline consent
      await coordinator.respondConsent(declineReq!.transferId, false, 'not authorized');

      const decision = await consentPromise;
      expect(decision).toBe(false);

      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 10));

      const err = reportedError as Error | null;
      expect(err).not.toBeNull();
      expect(err?.message).toContain('declined');

      coordinator.stop();
    });
  });
});
