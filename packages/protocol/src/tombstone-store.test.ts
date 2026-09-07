import { beforeEach, describe, expect, it } from 'vitest';
import { bytesToHex } from './bytes.js';
import {
  ERR_REVOCATION_SEQ_ROLLBACK,
  ERR_REVOCATION_UNAUTHORIZED,
  ERR_UNKNOWN_REVOKER,
} from './errors.js';
import { createDeviceIdentityFromSeed } from './identity.js';
import { IndexedDBTombstoneStore } from './indexeddb-tombstone-store.js';
import {
  ingestRevocationRecord,
  isSelfTombstone,
  signRevocation,
  signSelfTombstone,
} from './revocation.js';
import { MemoryTombstoneStore } from './tombstone-store.js';
import {
  MemoryTrustStore,
  RELATIONSHIP_CLUSTER_MEMBER,
  RELATIONSHIP_CONTACT,
} from './trust-store.js';

class MockObjectStore {
  constructor(public data = new Map<string, unknown>()) {}
  get(key: string) {
    const req: Record<string, unknown> = {
      result: this.data.get(key),
      onsuccess: null,
      onerror: null,
    };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
  getAll() {
    const req: Record<string, unknown> = {
      result: Array.from(this.data.values()),
      onsuccess: null,
      onerror: null,
    };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
  put(value: unknown, key?: string) {
    const k = key || (value as { revoked_device_id?: string })?.revoked_device_id || 'default';
    this.data.set(k, value);
    const req: Record<string, unknown> = {
      onsuccess: null,
      onerror: null,
    };
    queueMicrotask(() => (req.onsuccess as ((ev?: unknown) => void) | null)?.());
    return req;
  }
  delete(key: string) {
    this.data.delete(key);
  }
}

class MockDatabase {
  stores = new Map<string, MockObjectStore>();
  objectStoreNames = {
    contains: (name: string) => this.stores.has(name),
  };
  createObjectStore(name: string) {
    const store = new MockObjectStore();
    this.stores.set(name, store);
    return store;
  }
  transaction(storeNames: string[], _mode: string) {
    void _mode;
    const firstStore = this.stores.get(storeNames[0]!) || this.createObjectStore(storeNames[0]!);
    let aborted = false;
    const tx: Record<string, unknown> = {
      objectStore: (_name: string) => {
        void _name;
        return firstStore;
      },
      oncomplete: null,
      onerror: null,
      error: null,
      abort: () => {
        aborted = true;
      },
    };
    setTimeout(() => {
      if (!aborted) {
        (tx.oncomplete as ((ev?: unknown) => void) | null)?.();
      } else {
        (tx.onerror as ((ev?: unknown) => void) | null)?.();
      }
    }, 0);
    return tx;
  }
}

class MockIDBFactory {
  databases = new Map<string, MockDatabase>();
  open(name: string, version: number) {
    void version;
    const db = this.databases.get(name) || new MockDatabase();
    this.databases.set(name, db);
    const req: Record<string, unknown> = {
      result: db,
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
    };
    queueMicrotask(() => {
      (req.onupgradeneeded as ((ev?: unknown) => void) | null)?.();
      (req.onsuccess as ((ev?: unknown) => void) | null)?.();
    });
    return req;
  }
}

describe('TombstoneStore and Authorization Lifecycle (ADR 0010)', () => {
  let idAlice: Awaited<ReturnType<typeof createDeviceIdentityFromSeed>>;
  let idBob: Awaited<ReturnType<typeof createDeviceIdentityFromSeed>>;
  let idEve: Awaited<ReturnType<typeof createDeviceIdentityFromSeed>>;

  beforeEach(async () => {
    idAlice = await createDeviceIdentityFromSeed(new Uint8Array(32).fill(1));
    idBob = await createDeviceIdentityFromSeed(new Uint8Array(32).fill(2));
    idEve = await createDeviceIdentityFromSeed(new Uint8Array(32).fill(3));
  });

  it('MemoryTombstoneStore stores and enforces monotonic sequence rollback', async () => {
    const store = new MemoryTombstoneStore();
    const now = new Date('2026-09-07T06:00:00Z');

    const recSeq5 = await signRevocation(idAlice, idBob.deviceId, 5, now);
    await store.storeTombstone(recSeq5);

    expect(await store.hasTombstone(idBob.deviceId)).toBe(true);
    expect(await store.hasTombstone(idEve.deviceId)).toBe(false);

    const retrieved = await store.getTombstone(idBob.deviceId);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.seq).toBe(5);

    // Rollback attempt (seq 3 <= 5) is rejected
    const recSeq3 = await signRevocation(idAlice, idBob.deviceId, 3, now);
    await expect(store.storeTombstone(recSeq3)).rejects.toThrow(ERR_REVOCATION_SEQ_ROLLBACK);

    // Identical sequence (seq 5 <= 5) is rejected
    await expect(store.storeTombstone(recSeq5)).rejects.toThrow(ERR_REVOCATION_SEQ_ROLLBACK);

    // Forward sequence (seq 6 > 5) succeeds
    const recSeq6 = await signRevocation(idAlice, idBob.deviceId, 6, now);
    await store.storeTombstone(recSeq6);
    const updated = await store.getTombstone(idBob.deviceId);
    expect(updated?.seq).toBe(6);

    // Self-tombstone
    const selfTomb = await signSelfTombstone(idAlice, 1, now);
    expect(isSelfTombstone(selfTomb)).toBe(true);
    await store.storeTombstone(selfTomb);
    expect(await store.hasTombstone(idAlice.deviceId)).toBe(true);

    const all = await store.listTombstones();
    expect(all.length).toBe(2);
  });

  it('IndexedDBTombstoneStore stores and enforces monotonic sequence', async () => {
    const mockIdb = new MockIDBFactory();
    const store = new IndexedDBTombstoneStore(mockIdb as unknown as IDBFactory);
    const now = new Date('2026-09-07T06:00:00Z');

    const rec = await signRevocation(idAlice, idBob.deviceId, 10, now);
    await store.storeTombstone(rec);

    expect(await store.hasTombstone(idBob.deviceId)).toBe(true);
    const retrieved = await store.getTombstone(idBob.deviceId);
    expect(retrieved?.seq).toBe(10);

    const stale = await signRevocation(idAlice, idBob.deviceId, 4, now);
    await expect(store.storeTombstone(stale)).rejects.toThrow(ERR_REVOCATION_SEQ_ROLLBACK);
  });

  it('Authorization: External contacts cannot revoke third parties across mesh', async () => {
    const trustStore = new MemoryTrustStore();
    const tombstoneStore = new MemoryTombstoneStore();
    const now = new Date().toISOString();

    // Alice is an external contact
    await trustStore.addOrUpdateDevice({
      deviceId: idAlice.deviceId,
      publicKey: bytesToHex(idAlice.publicKey),
      localLabel: 'Alice Contact',
      pairCredentialRef: 'cred-alice',
      relationship: RELATIONSHIP_CONTACT,
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
    });

    // Bob is another contact
    await trustStore.addOrUpdateDevice({
      deviceId: idBob.deviceId,
      publicKey: bytesToHex(idBob.publicKey),
      localLabel: 'Bob Contact',
      pairCredentialRef: 'cred-bob',
      relationship: RELATIONSHIP_CONTACT,
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
    });

    // Alice tries to revoke Bob -> MUST BE REJECTED fail-closed with ERR_REVOCATION_UNAUTHORIZED
    const aliceRevokingBob = await signRevocation(idAlice, idBob.deviceId, 1);
    await expect(
      ingestRevocationRecord(aliceRevokingBob, trustStore, { tombstoneStore }),
    ).rejects.toThrow(ERR_REVOCATION_UNAUTHORIZED);

    // Bob MUST remain trusted
    expect(await trustStore.isTrusted(idBob.deviceId)).toBe(true);
    expect(await tombstoneStore.hasTombstone(idBob.deviceId)).toBe(false);

    // But Alice CAN revoke herself (self-tombstone is universally authorized)
    const aliceSelfTomb = await signSelfTombstone(idAlice, 1);
    await ingestRevocationRecord(aliceSelfTomb, trustStore, { tombstoneStore });
    expect(await trustStore.isTrusted(idAlice.deviceId)).toBe(false);
    expect(await tombstoneStore.hasTombstone(idAlice.deviceId)).toBe(true);
  });

  it('Authorization: Cluster member can revoke devices within cluster and abort sessions', async () => {
    const trustStore = new MemoryTrustStore();
    const tombstoneStore = new MemoryTombstoneStore();
    const now = new Date().toISOString();
    const clusterId = 'sb-cluster-test-123';

    // Alice and Bob are cluster members
    await trustStore.addOrUpdateDevice({
      deviceId: idAlice.deviceId,
      publicKey: bytesToHex(idAlice.publicKey),
      localLabel: 'Alice Laptop',
      pairCredentialRef: 'cred-alice',
      relationship: RELATIONSHIP_CLUSTER_MEMBER,
      clusterId,
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
    });

    await trustStore.addOrUpdateDevice({
      deviceId: idBob.deviceId,
      publicKey: bytesToHex(idBob.publicKey),
      localLabel: 'Bob Phone',
      pairCredentialRef: 'cred-bob',
      relationship: RELATIONSHIP_CLUSTER_MEMBER,
      clusterId,
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
    });

    let abortedDevice = '';
    const aliceRevokingBob = await signRevocation(idAlice, idBob.deviceId, 1);
    await ingestRevocationRecord(aliceRevokingBob, trustStore, {
      tombstoneStore,
      localClusterId: clusterId,
      onAbortSession: (devId) => {
        abortedDevice = devId;
      },
    });

    expect(await trustStore.isTrusted(idBob.deviceId)).toBe(false);
    expect(await tombstoneStore.hasTombstone(idBob.deviceId)).toBe(true);
    expect(abortedDevice).toBe(idBob.deviceId);

    const bob = await trustStore.getDevice(idBob.deviceId);
    expect(bob?.revoked).toBe(true);
    expect(bob?.revokedBy).toBe(idAlice.deviceId);
  });

  it('Unknown revoker self-tombstone is saved to deny-list to prevent future pairing', async () => {
    const trustStore = new MemoryTrustStore();
    const tombstoneStore = new MemoryTombstoneStore();

    // Unknown device Eve emits self-tombstone
    const eveSelfTomb = await signSelfTombstone(idEve, 1);
    await ingestRevocationRecord(eveSelfTomb, trustStore, { tombstoneStore });

    // Eve is not in trustStore, but is now denied in tombstoneStore
    expect(await tombstoneStore.hasTombstone(idEve.deviceId)).toBe(true);

    // But an unknown device trying to revoke Bob fails closed
    const eveRevokingBob = await signRevocation(idEve, idBob.deviceId, 1);
    await expect(
      ingestRevocationRecord(eveRevokingBob, trustStore, { tombstoneStore }),
    ).rejects.toThrow(ERR_UNKNOWN_REVOKER);
  });
});
