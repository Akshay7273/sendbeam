import { describe, it, expect, beforeEach } from 'vitest';
import {
  listTrustedDevices,
  renameTrustedDevice,
  updateTrustedDevicePolicy,
  unpairTrustedDevice,
  pairTrustedDevice,
  startPairingOffer,
  resetBrowserStoresForTesting,
} from './devices.js';
import {
  generateDeviceIdentity,
  deriveDeviceId,
  formatFingerprint,
  bytesToHex,
  MemoryTrustStore,
  MemoryTombstoneStore,
  MemorySecretResolver,
} from '@sendbeam/protocol';

describe('Trusted Devices Frontend Bridge', () => {
  beforeEach(() => {
    // Ensure clean window mock
    if (typeof window !== 'undefined') {
      delete (window as unknown as Record<string, unknown>).go;
    }
  });

  it('lists fallback in-memory devices when not running in Wails', async () => {
    const list = await listTrustedDevices();
    expect(Array.isArray(list)).toBe(true);
  });

  it('interacts with mock desktop Wails DeviceService when available', async () => {
    const kp = await generateDeviceIdentity();
    const devId = await deriveDeviceId(kp.publicKey);
    const pubHex = bytesToHex(kp.publicKey);
    const fp = formatFingerprint(kp.publicKey);

    const mockDevices = [
      {
        deviceId: devId,
        localLabel: 'Work MacBook',
        fingerprint: fp,
        publicKey: pubHex,
        status: 'lan_direct' as const,
        revoked: false,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1', 'lan_direct'],
        policy: { autoAccept: true, autoAcceptDestDir: '/home/user/Downloads' },
      },
    ];

    let renameCalledWith: [string, string] | null = null;
    let policyCalledWith: unknown = null;
    let unpairCalledWith: [string, boolean] | null = null;

    globalThis.window = {
      go: {
        engine: {
          DeviceService: {
            ListTrustedDevices: async () => mockDevices,
            RenameDevice: async (id: string, name: string) => {
              renameCalledWith = [id, name];
            },
            UpdateDevicePolicy: async (id: string, pol: unknown) => {
              policyCalledWith = pol;
            },
            UnpairDevice: async (id: string, purge: boolean) => {
              unpairCalledWith = [id, purge];
            },
            PairDevice: async () => mockDevices[0]!,
          },
        },
      },
    } as unknown as Window & typeof globalThis;

    const devs = await listTrustedDevices();
    expect(devs).toHaveLength(1);
    expect(devs[0]!.localLabel).toBe('Work MacBook');
    expect(devs[0]!.status).toBe('lan_direct');
    expect(devs[0]!.policy.autoAccept).toBe(true);

    await renameTrustedDevice(devId, 'Work Laptop Pro');
    expect(renameCalledWith).toEqual([devId, 'Work Laptop Pro']);

    await updateTrustedDevicePolicy(devId, { autoAccept: false });
    expect(policyCalledWith).toEqual({ autoAccept: false });

    await unpairTrustedDevice(devId, true);
    expect(unpairCalledWith).toEqual([devId, true]);
  });

  it('maps mesh-synced revocation provenance accurately', async () => {
    const kp = await generateDeviceIdentity();
    const devId = await deriveDeviceId(kp.publicKey);
    const pubHex = bytesToHex(kp.publicKey);
    const fp = formatFingerprint(kp.publicKey);

    const mockDevices = [
      {
        deviceId: devId,
        localLabel: 'Compromised Phone',
        fingerprint: fp,
        publicKey: pubHex,
        status: 'revoked' as const,
        revoked: true,
        revokedBy: 'sb-dev-laptop1234567890',
        revocationSeq: 1,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1'],
        policy: { autoAccept: false },
      },
    ];

    globalThis.window = {
      go: {
        engine: {
          DeviceService: {
            ListTrustedDevices: async () => mockDevices,
          },
        },
      },
    } as unknown as Window & typeof globalThis;

    const devs = await listTrustedDevices();
    expect(devs).toHaveLength(1);
    expect(devs[0]!.status).toBe('revoked');
    expect(devs[0]!.revoked).toBe(true);
    expect(devs[0]!.revokedBy).toBe('sb-dev-laptop1234567890');
    expect(devs[0]!.revocationSeq).toBe(1);
  });

  it('supports multi-device filtering for broadcast sends', async () => {
    const mockDevices = [
      {
        deviceId: 'dev-1',
        localLabel: 'Work Laptop',
        fingerprint: '1234 5678',
        publicKey: '001122',
        status: 'lan_direct' as const,
        revoked: false,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1'],
        policy: { autoAccept: true },
      },
      {
        deviceId: 'dev-2',
        localLabel: 'Phone',
        fingerprint: '5678 1234',
        publicKey: '223344',
        status: 'online' as const,
        revoked: false,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1'],
        policy: { autoAccept: false },
      },
      {
        deviceId: 'dev-3',
        localLabel: 'Old Tablet',
        fingerprint: '9999 0000',
        publicKey: '445566',
        status: 'revoked' as const,
        revoked: true,
        lastSeenAt: new Date().toISOString(),
        firstSeenAt: new Date().toISOString(),
        capabilities: ['transfer.v1'],
        policy: { autoAccept: false },
      },
    ];

    globalThis.window = {
      go: {
        engine: {
          DeviceService: {
            ListTrustedDevices: async () => mockDevices,
          },
        },
      },
    } as unknown as Window & typeof globalThis;

    const devs = await listTrustedDevices();
    expect(devs).toHaveLength(3);
    const sendable = devs.filter((d) => !d.revoked);
    expect(sendable).toHaveLength(2);
    expect(sendable.map((d) => d.localLabel)).toEqual(['Work Laptop', 'Phone']);
  });

  it('unpairs and creates authorized signed tombstone in browser mode', async () => {
    // Inject in-memory stores for browser environment
    const trustStore = new MemoryTrustStore();
    const tombstoneStore = new MemoryTombstoneStore();
    const secretStore = new MemorySecretResolver();
    resetBrowserStoresForTesting(trustStore, secretStore, tombstoneStore);

    const peerId = await generateDeviceIdentity();
    const peerDevId = peerId.deviceId;
    const pubHex = bytesToHex(peerId.publicKey);

    // Register active peer device and pairwise secret
    await trustStore.addOrUpdateDevice({
      deviceId: peerDevId,
      localLabel: 'Peer Tablet',
      publicKey: pubHex,
      pairCredentialRef: 'cred-peer-1',
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    });
    await secretStore.setPairSecret(peerDevId, new Uint8Array(32));

    // Verify peer is active and secret exists
    expect(await trustStore.isTrusted(peerDevId)).toBe(true);
    expect(await secretStore.getPairSecret(peerDevId)).not.toBeNull();

    // Revoke peer (purge = false)
    await unpairTrustedDevice(peerDevId, false);

    // Record must be marked revoked with provenance in trustStore
    const revokedDev = await trustStore.getDevice(peerDevId);
    expect(revokedDev).not.toBeNull();
    expect(revokedDev?.revoked).toBe(true);
    expect(revokedDev?.revocationSeq).toBe(1);
    expect(revokedDev?.revokedBy).toBeDefined();
    expect(revokedDev?.revocationSig).toBeDefined();

    // Tombstone must be created in tombstoneStore
    const hasTomb = await tombstoneStore.hasTombstone(peerDevId);
    expect(hasTomb).toBe(true);
    const tomb = await tombstoneStore.getTombstone(peerDevId);
    expect(tomb?.revoked_device_id).toBe(peerDevId);
    expect(tomb?.seq).toBe(1);

    // Secret must be purged from secretStore
    expect(await secretStore.getPairSecret(peerDevId)).toBeNull();

    // Now test purge = true
    await unpairTrustedDevice(peerDevId, true);
    expect(await trustStore.getDevice(peerDevId)).toBeNull();
    // Tombstone remains intact
    expect(await tombstoneStore.hasTombstone(peerDevId)).toBe(true);
  });

  it('validates invite code when pairing in browser mode', async () => {
    resetBrowserStoresForTesting(
      new MemoryTrustStore(),
      new MemorySecretResolver(),
      new MemoryTombstoneStore(),
    );

    await expect(pairTrustedDevice('', '', 'Laptop', false, '')).rejects.toThrow(
      'invite code is required',
    );
  });

  it('renames and updates policy in browser mode', async () => {
    const trustStore = new MemoryTrustStore();
    resetBrowserStoresForTesting(
      trustStore,
      new MemorySecretResolver(),
      new MemoryTombstoneStore(),
    );

    const peerId = await generateDeviceIdentity();
    const peerDevId = peerId.deviceId;

    await trustStore.addOrUpdateDevice({
      deviceId: peerDevId,
      localLabel: 'Old Name',
      publicKey: bytesToHex(peerId.publicKey),
      pairCredentialRef: 'ref-1',
      capabilities: ['transfer.v1'],
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revoked: false,
      policy: { autoAccept: false },
    });

    await renameTrustedDevice(peerDevId, 'New Renamed Device');
    let dev = await trustStore.getDevice(peerDevId);
    expect(dev?.localLabel).toBe('New Renamed Device');

    await updateTrustedDevicePolicy(peerDevId, {
      autoAccept: true,
      autoAcceptDestDir: '/downloads',
    });
    dev = await trustStore.getDevice(peerDevId);
    expect(dev?.policy.autoAccept).toBe(true);
    expect(dev?.policy.autoAcceptDestDir).toBe('/downloads');
  });

  it('initiates pairing offer and allows clean cancellation in browser mode', async () => {
    const trustStore = new MemoryTrustStore();
    resetBrowserStoresForTesting(
      trustStore,
      new MemorySecretResolver(),
      new MemoryTombstoneStore(),
    );

    const ctrl = startPairingOffer({
      name: 'Offerer Browser',
      autoAccept: false,
    });

    expect(typeof ctrl.cancel).toBe('function');
    ctrl.cancel('user cancelled pairing');
    await expect(ctrl.done).rejects.toBeDefined();
  });
});
