/**
 * Persistent TombstoneStore implementation over IndexedDB (ADR 0010 §4.5).
 */

import { ERR_REVOCATION_SEQ_ROLLBACK } from './errors.js';
import { type RevocationRecord, validateRevocationRecord } from './revocation.js';
import type { TombstoneStore } from './tombstone-store.js';

export const TOMBSTONE_DB_NAME = 'sendbeam-tombstones';
export const TOMBSTONES_STORE = 'tombstones';

export class IndexedDBTombstoneStore implements TombstoneStore {
  private readonly customIdb: IDBFactory | undefined;
  private dbPromise: Promise<IDBDatabase> | undefined;

  constructor(customIdb?: IDBFactory) {
    this.customIdb = customIdb;
  }

  private getDb(): Promise<IDBDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const idb = this.customIdb ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
        if (!idb) {
          reject(new Error('IndexedDB is unavailable in this environment'));
          return;
        }

        const req = idb.open(TOMBSTONE_DB_NAME, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(TOMBSTONES_STORE)) {
            db.createObjectStore(TOMBSTONES_STORE, { keyPath: 'revoked_device_id' });
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('failed to open tombstone database'));
      });
    }
    return this.dbPromise;
  }

  async storeTombstone(record: RevocationRecord): Promise<void> {
    validateRevocationRecord(record);
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TOMBSTONES_STORE], 'readwrite');
      const store = tx.objectStore(TOMBSTONES_STORE);
      const getReq = store.get(record.revoked_device_id);
      getReq.onsuccess = () => {
        const existing = getReq.result as RevocationRecord | undefined;
        if (
          existing &&
          existing.revoker_device_id === record.revoker_device_id &&
          record.seq <= existing.seq
        ) {
          tx.abort();
          reject(new Error(ERR_REVOCATION_SEQ_ROLLBACK));
          return;
        }
        store.put(record);
      };
      getReq.onerror = () => {
        tx.abort();
        reject(getReq.error ?? new Error('failed to read existing tombstone'));
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('failed to store tombstone'));
    });
  }

  async getTombstone(deviceId: string): Promise<RevocationRecord | null> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TOMBSTONES_STORE], 'readonly');
      const req = tx.objectStore(TOMBSTONES_STORE).get(deviceId);
      req.onsuccess = () => resolve((req.result as RevocationRecord) ?? null);
      req.onerror = () => reject(req.error ?? new Error('failed to get tombstone'));
    });
  }

  async hasTombstone(deviceId: string): Promise<boolean> {
    const tomb = await this.getTombstone(deviceId);
    return tomb !== null;
  }

  async listTombstones(): Promise<RevocationRecord[]> {
    const db = await this.getDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([TOMBSTONES_STORE], 'readonly');
      const req = tx.objectStore(TOMBSTONES_STORE).getAll();
      req.onsuccess = () => resolve((req.result as RevocationRecord[]) ?? []);
      req.onerror = () => reject(req.error ?? new Error('failed to list tombstones'));
    });
  }
}
