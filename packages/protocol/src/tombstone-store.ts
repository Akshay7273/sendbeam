/**
 * Persistent and in-memory storage for signed revocation tombstones (ADR 0010 §4.5).
 */

import { ERR_REVOCATION_SEQ_ROLLBACK } from './errors.js';
import { type RevocationRecord, validateRevocationRecord } from './revocation.js';

/**
 * TombstoneStore defines the interface for persisting and querying signed revocation tombstones.
 */
export interface TombstoneStore {
  storeTombstone(record: RevocationRecord): Promise<void>;
  getTombstone(deviceId: string): Promise<RevocationRecord | null>;
  hasTombstone(deviceId: string): Promise<boolean>;
  listTombstones(): Promise<RevocationRecord[]>;
}

/**
 * MemoryTombstoneStore is an in-memory implementation of TombstoneStore.
 */
export class MemoryTombstoneStore implements TombstoneStore {
  private readonly tombstones = new Map<string, RevocationRecord>();

  async storeTombstone(record: RevocationRecord): Promise<void> {
    validateRevocationRecord(record);
    const existing = this.tombstones.get(record.revoked_device_id);
    if (
      existing &&
      existing.revoker_device_id === record.revoker_device_id &&
      record.seq <= existing.seq
    ) {
      throw new Error(ERR_REVOCATION_SEQ_ROLLBACK);
    }
    this.tombstones.set(record.revoked_device_id, { ...record });
  }

  async getTombstone(deviceId: string): Promise<RevocationRecord | null> {
    const rec = this.tombstones.get(deviceId);
    if (!rec) return null;
    return { ...rec };
  }

  async hasTombstone(deviceId: string): Promise<boolean> {
    return this.tombstones.has(deviceId);
  }

  async listTombstones(): Promise<RevocationRecord[]> {
    return Array.from(this.tombstones.values()).map((r) => ({ ...r }));
  }
}
