/**
 * Streaming, store-only ZIP primitives (no compression). Shared by the browser archive sink
 * and the durable-receive finalize step, which builds a ZIP from verified partials.
 *
 * ZIP64 support: entries above `zip64Limits.size` use ZIP64 local headers, 64-bit data
 * descriptors, and ZIP64 central-directory extra fields; the end-of-central-directory then
 * emits the ZIP64 EOCD record plus locator. The limit is a mutable export so tests can force
 * the ZIP64 path with small data and validate the result with real ZIP readers.
 */

export interface ZipEntry {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
}

/**
 * ZIP64 thresholds. Sizes/offsets strictly above `size` and entry counts strictly above
 * `count` take the 64-bit record path. Mutable so tests can force the ZIP64 path with small
 * data and validate the result with real ZIP readers; production code never changes these.
 */
export const zip64Limits = { size: 0xffffffff, count: 0xffff };

const ZIP64_EXTRA_TAG = 0x0001;
const VERSION_ZIP64 = 45;

export function entryNeedsZip64(entry: Pick<ZipEntry, 'size' | 'offset'>): boolean {
  return entry.size > zip64Limits.size || entry.offset > zip64Limits.size;
}

const crcTable = Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  return crc >>> 0;
});

export function crc32Update(crc: number, bytes: Uint8Array): number {
  for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff]!;
  return crc >>> 0;
}

function record(size: number, write: (view: DataView) => void): Uint8Array {
  const out = new Uint8Array(size);
  write(new DataView(out.buffer));
  return out;
}

function setUint64(view: DataView, byteOffset: number, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new RangeError(`ZIP64 field needs a safe non-negative integer, got ${value}`);
  view.setBigUint64(byteOffset, BigInt(value), true);
}

/**
 * Local file header. `size` is the declared (manifest/journal) size: when it needs ZIP64 the
 * header carries version 45, 0xFFFFFFFF size markers, and a ZIP64 extra field with the true
 * sizes. Smaller entries keep the classic layout with a data descriptor (sizes resolved at
 * the descriptor, which streaming requires).
 */
export function localHeader(name: Uint8Array, size: number): Uint8Array {
  if (size <= zip64Limits.size) {
    const header = record(30, (v) => {
      v.setUint32(0, 0x04034b50, true);
      v.setUint16(4, 20, true);
      v.setUint16(6, 0x0808, true);
      v.setUint16(26, name.length, true);
    });
    return join(header, name);
  }
  const header = record(30, (v) => {
    v.setUint32(0, 0x04034b50, true);
    v.setUint16(4, VERSION_ZIP64, true);
    v.setUint16(6, 0x0808, true);
    v.setUint16(8, 0, true); // method: store
    v.setUint32(14, 0, true); // crc: resolved by the data descriptor
    v.setUint32(18, 0xffffffff, true); // compressed size marker
    v.setUint32(22, 0xffffffff, true); // uncompressed size marker
    v.setUint16(26, name.length, true);
    v.setUint16(28, 20, true); // extra field length
  });
  // APPNOTE order: filename first, then the extra field.
  const extra = record(20, (v) => {
    v.setUint16(0, ZIP64_EXTRA_TAG, true);
    v.setUint16(2, 16, true);
    setUint64(v, 4, size); // uncompressed size
    setUint64(v, 12, size); // compressed size (store: identical)
  });
  return join(header, name, extra);
}

/** Data descriptor, 16 bytes classic or 24 bytes with 64-bit sizes for ZIP64 entries. */
export function dataDescriptor(crc: number, size: number): Uint8Array {
  if (size <= zip64Limits.size) {
    return record(16, (v) => {
      v.setUint32(0, 0x08074b50, true);
      v.setUint32(4, crc, true);
      v.setUint32(8, size, true);
      v.setUint32(12, size, true);
    });
  }
  return record(24, (v) => {
    v.setUint32(0, 0x08074b50, true);
    v.setUint32(4, crc, true);
    setUint64(v, 8, size); // compressed size
    setUint64(v, 16, size); // uncompressed size
  });
}

/** Central directory header with a ZIP64 extra field when the entry needs it. */
export function centralHeader(entry: ZipEntry): Uint8Array {
  if (!entryNeedsZip64(entry)) {
    const header = record(46, (v) => {
      v.setUint32(0, 0x02014b50, true);
      v.setUint16(4, 20, true);
      v.setUint16(6, 20, true);
      v.setUint16(8, 0x0808, true);
      v.setUint32(16, entry.crc, true);
      v.setUint32(20, entry.size, true);
      v.setUint32(24, entry.size, true);
      v.setUint16(28, entry.name.length, true);
      v.setUint32(42, entry.offset, true);
    });
    return join(header, entry.name);
  }
  const header = record(46, (v) => {
    v.setUint32(0, 0x02014b50, true);
    v.setUint16(4, VERSION_ZIP64, true); // version made by
    v.setUint16(6, VERSION_ZIP64, true); // version needed
    v.setUint16(8, 0x0808, true);
    v.setUint32(16, entry.crc, true);
    v.setUint32(20, 0xffffffff, true); // compressed size marker
    v.setUint32(24, 0xffffffff, true); // uncompressed size marker
    v.setUint16(28, entry.name.length, true);
    v.setUint16(30, 28, true); // extra field length
    v.setUint32(42, 0xffffffff, true); // local header offset marker
  });
  // APPNOTE order: filename first, then the extra field.
  const extra = record(28, (v) => {
    v.setUint16(0, ZIP64_EXTRA_TAG, true);
    v.setUint16(2, 24, true);
    setUint64(v, 4, entry.size); // uncompressed size
    setUint64(v, 12, entry.size); // compressed size
    setUint64(v, 20, entry.offset); // local header offset
  });
  return join(header, entry.name, extra);
}

/**
 * End of central directory. When `zip64` is set, emits the ZIP64 EOCD record, the ZIP64 EOCD
 * locator, and a classic EOCD with 0xFFFF/0xFFFFFFFF markers; otherwise the classic 22-byte
 * record. Callers set `zip64` when any entry needed ZIP64 or a count/size/offset overflows
 * 32 bits.
 */
export function endOfCentralDirectory(
  count: number,
  size: number,
  offset: number,
  zip64: boolean,
): Uint8Array {
  if (!zip64) {
    return record(22, (v) => {
      v.setUint32(0, 0x06054b50, true);
      v.setUint16(8, count, true);
      v.setUint16(10, count, true);
      v.setUint32(12, size, true);
      v.setUint32(16, offset, true);
    });
  }
  const eocd = record(56, (v) => {
    v.setUint32(0, 0x06064b50, true); // ZIP64 EOCD signature
    setUint64(v, 4, 44); // size of this record
    v.setUint16(12, VERSION_ZIP64, true); // version made by
    v.setUint16(14, VERSION_ZIP64, true); // version needed
    v.setUint32(16, 0, true); // disk number
    v.setUint32(20, 0, true); // disk with central directory
    setUint64(v, 24, count); // entries on this disk
    setUint64(v, 32, count); // total entries
    setUint64(v, 40, size); // central directory size
    setUint64(v, 48, offset); // central directory offset
  });
  const locator = record(20, (v) => {
    v.setUint32(0, 0x07064b50, true); // ZIP64 EOCD locator signature
    v.setUint32(4, 0, true); // disk with the ZIP64 EOCD
    setUint64(v, 8, offset + size); // offset of the ZIP64 EOCD
    v.setUint32(16, 1, true); // total disks
  });
  const classic = record(22, (v) => {
    v.setUint32(0, 0x06054b50, true);
    v.setUint16(8, 0xffff, true);
    v.setUint16(10, 0xffff, true);
    v.setUint32(12, 0xffffffff, true);
    v.setUint32(16, 0xffffffff, true);
  });
  return join(eocd, locator, classic);
}

function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
