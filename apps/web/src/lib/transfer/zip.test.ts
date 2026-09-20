import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FrameType, type Manifest } from '@sendbeam/protocol';
import {
  centralHeader,
  crc32Update,
  dataDescriptor,
  endOfCentralDirectory,
  entryNeedsZip64,
  localHeader,
  zip64Limits,
  type ZipEntry,
} from './zip.js';
import { MemoryBlobDestination } from './sink.js';

const PRODUCTION_LIMIT = 0xffffffff;

afterEach(() => {
  zip64Limits.size = PRODUCTION_LIMIT;
  zip64Limits.count = 0xffff;
});

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

describe('classic layouts are unchanged for small entries', () => {
  it('local header stays version 20 without ZIP64', () => {
    const name = new TextEncoder().encode('a.bin');
    const header = localHeader(name, 3);
    expect(header.length).toBe(30 + name.length);
    expect(view(header).getUint16(4, true)).toBe(20);
    expect(view(header).getUint16(28, true)).toBe(0);
  });

  it('data descriptor stays 16 bytes without ZIP64', () => {
    const desc = dataDescriptor(0x55bc801d, 3);
    expect(desc.length).toBe(16);
    expect(view(desc).getUint32(0, true)).toBe(0x08074b50);
    expect(view(desc).getUint32(8, true)).toBe(3);
  });

  it('central header stays classic without ZIP64', () => {
    const name = new TextEncoder().encode('a.bin');
    const header = centralHeader({ name, crc: 1, size: 3, offset: 30 });
    expect(header.length).toBe(46 + name.length);
    expect(view(header).getUint16(6, true)).toBe(20);
    expect(view(header).getUint32(20, true)).toBe(3);
  });

  it('end of central directory stays classic when not requested', () => {
    const eocd = endOfCentralDirectory(2, 300, 1000, false);
    expect(eocd.length).toBe(22);
    expect(view(eocd).getUint32(0, true)).toBe(0x06054b50);
    expect(view(eocd).getUint16(8, true)).toBe(2);
    expect(view(eocd).getUint32(16, true)).toBe(1000);
  });
});

describe('ZIP64 record layouts', () => {
  const big = 5_000_000_000;

  it('local header uses version 45, markers, and a ZIP64 extra field after the name', () => {
    const name = new TextEncoder().encode('big.bin');
    const header = localHeader(name, big);
    const v = view(header);
    expect(header.length).toBe(30 + name.length + 20);
    expect(v.getUint32(0, true)).toBe(0x04034b50);
    expect(v.getUint16(4, true)).toBe(45);
    expect(v.getUint32(18, true)).toBe(0xffffffff);
    expect(v.getUint32(22, true)).toBe(0xffffffff);
    expect(v.getUint16(28, true)).toBe(20);
    // APPNOTE order: filename, then the extra field.
    expect(new TextDecoder().decode(header.slice(30, 30 + name.length))).toBe('big.bin');
    const extraAt = 30 + name.length;
    expect(v.getUint16(extraAt, true)).toBe(0x0001);
    expect(v.getUint16(extraAt + 2, true)).toBe(16);
    expect(v.getBigUint64(extraAt + 4, true)).toBe(BigInt(big));
    expect(v.getBigUint64(extraAt + 12, true)).toBe(BigInt(big));
  });

  it('data descriptor grows to 24 bytes with 64-bit sizes', () => {
    const desc = dataDescriptor(0x12345678, big);
    const v = view(desc);
    expect(desc.length).toBe(24);
    expect(v.getUint32(0, true)).toBe(0x08074b50);
    expect(v.getUint32(4, true)).toBe(0x12345678);
    expect(v.getBigUint64(8, true)).toBe(BigInt(big));
    expect(v.getBigUint64(16, true)).toBe(BigInt(big));
  });

  it('central header carries the ZIP64 extra field with true values', () => {
    const name = new TextEncoder().encode('big.bin');
    const entry: ZipEntry = { name, crc: 0x12345678, size: big, offset: 6_000_000_000 };
    expect(entryNeedsZip64(entry)).toBe(true);
    const header = centralHeader(entry);
    const v = view(header);
    expect(header.length).toBe(46 + name.length + 28);
    expect(v.getUint16(6, true)).toBe(45);
    expect(v.getUint32(20, true)).toBe(0xffffffff);
    expect(v.getUint32(42, true)).toBe(0xffffffff);
    // APPNOTE order: filename, then the extra field.
    expect(new TextDecoder().decode(header.slice(46, 46 + name.length))).toBe('big.bin');
    const extraAt = 46 + name.length;
    expect(v.getUint16(extraAt, true)).toBe(0x0001);
    expect(v.getUint16(extraAt + 2, true)).toBe(24);
    expect(v.getBigUint64(extraAt + 4, true)).toBe(BigInt(big));
    expect(v.getBigUint64(extraAt + 12, true)).toBe(BigInt(big));
    expect(v.getBigUint64(extraAt + 20, true)).toBe(6_000_000_000n);
  });

  it('ZIP64 end of central directory chains EOCD, locator, and classic markers', () => {
    const eocd = endOfCentralDirectory(2, 300, 1000, true);
    const v = view(eocd);
    expect(eocd.length).toBe(56 + 20 + 22);
    expect(v.getUint32(0, true)).toBe(0x06064b50);
    expect(v.getBigUint64(4, true)).toBe(44n);
    expect(v.getBigUint64(32, true)).toBe(2n);
    expect(v.getBigUint64(48, true)).toBe(1000n);
    // Locator immediately follows the 56-byte record.
    expect(v.getUint32(56, true)).toBe(0x07064b50);
    expect(v.getBigUint64(64, true)).toBe(1300n); // offset + size
    expect(v.getUint32(72, true)).toBe(1);
    // Classic EOCD closes the chain with overflow markers.
    expect(v.getUint32(76, true)).toBe(0x06054b50);
    expect(v.getUint16(84, true)).toBe(0xffff);
    expect(v.getUint32(88, true)).toBe(0xffffffff);
    expect(v.getUint32(92, true)).toBe(0xffffffff);
  });

  it('entryNeedsZip64 follows the mutable limit', () => {
    expect(entryNeedsZip64({ size: 100, offset: 0 })).toBe(false);
    zip64Limits.size = 16;
    expect(entryNeedsZip64({ size: 100, offset: 0 })).toBe(true);
    expect(entryNeedsZip64({ size: 0, offset: 100 })).toBe(true);
    expect(entryNeedsZip64({ size: 16, offset: 0 })).toBe(false);
  });
});

describe('forced-ZIP64 archive round-trips through real unzip', () => {
  function buildArchive(files: Array<{ name: string; data: Uint8Array }>): Uint8Array {
    const parts: Uint8Array[] = [];
    const entries: ZipEntry[] = [];
    let position = 0;
    for (const file of files) {
      const name = new TextEncoder().encode(file.name);
      const header = localHeader(name, file.data.length);
      const headerOffset = position;
      parts.push(header);
      position += header.length;
      parts.push(file.data);
      position += file.data.length;
      const crc = (crc32Update(0xffffffff, file.data) ^ 0xffffffff) >>> 0;
      const desc = dataDescriptor(crc, file.data.length);
      parts.push(desc);
      position += desc.length;
      entries.push({ name, crc, size: file.data.length, offset: headerOffset });
    }
    const centralOffset = position;
    let zip64 = entries.length > zip64Limits.count || centralOffset > zip64Limits.size;
    for (const entry of entries) {
      zip64 ||= entryNeedsZip64(entry);
      const header = centralHeader(entry);
      parts.push(header);
      position += header.length;
    }
    const centralSize = position - centralOffset;
    zip64 ||= centralSize > zip64Limits.size;
    parts.push(endOfCentralDirectory(entries.length, centralSize, centralOffset, zip64));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }

  it('validates with unzip when the ZIP64 path is forced', () => {
    zip64Limits.size = 16; // force every entry down the ZIP64 path with small data
    const payload = new Uint8Array(100).map((_, i) => i & 0xff);
    const archive = buildArchive([
      { name: 'folder/a.bin', data: payload },
      { name: 'folder/empty.txt', data: new Uint8Array(0) },
    ]);
    // The forced archive must actually contain ZIP64 records.
    expect(view(archive).getUint16(4, true)).toBe(45);
    expect(
      view(archive).getUint32(archive.length - 22, true),
    ).toBe(0x06054b50); // classic EOCD closes the chain

    const dir = mkdtempSync(join(tmpdir(), 'sendbeam-zip64-test-'));
    try {
      const path = join(dir, 'forced.zip');
      writeFileSync(path, archive);
      expect(execFileSync('unzip', ['-t', path], { encoding: 'utf8' })).toContain('No errors');
      expect(execFileSync('unzip', ['-p', path, 'folder/a.bin'])).toEqual(Buffer.from(payload));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('in-memory ZIP fallback writes valid CRCs', () => {
  function manifest(names: Array<[string, number]>): Manifest {
    return {
      type: FrameType.Manifest,
      files: names.map(([name, size], idx) => ({
        idx,
        name,
        size,
        mime: '',
        lastModified: 0,
        blockSize: 8,
        blocks: Math.ceil(size / 8),
        fileDigest: '00',
      })),
      totalSize: names.reduce((total, [, size]) => total + size, 0),
    };
  }

  it('MemoryBlobDestination archive passes unzip -t', async () => {
    const destination = new MemoryBlobDestination();
    const files = manifest([
      ['folder/a.bin', 3],
      ['folder/empty.txt', 0],
    ]);
    await destination.prepare(files);
    const first = await destination.open(files.files[0]!);
    await first.write(0, new Uint8Array([1, 2, 3]));
    await first.close();
    const second = await destination.open(files.files[1]!);
    await second.close();
    await destination.close();

    const output = destination.result();
    expect(output?.kind).toBe('blob');
    const bytes = new Uint8Array(await (output as { blob: Blob }).blob.arrayBuffer());

    const dir = mkdtempSync(join(tmpdir(), 'sendbeam-zipcrc-test-'));
    try {
      const path = join(dir, 'mem.zip');
      writeFileSync(path, bytes);
      expect(execFileSync('unzip', ['-t', path], { encoding: 'utf8' })).toContain('No errors');
      expect(execFileSync('unzip', ['-p', path, 'folder/a.bin'])).toEqual(
        Buffer.from([1, 2, 3]),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
