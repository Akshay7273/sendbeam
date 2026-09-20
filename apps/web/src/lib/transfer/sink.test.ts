import { afterEach, describe, expect, it, vi } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FrameType, type Manifest } from '@sendbeam/protocol';
import {
  ArchiveDestination,
  HandoffDestination,
  createBrowserDestination,
  readOpfsOutput,
  removeOpfsOutput,
} from './sink.js';
import type { WritableFileLike } from './stream-sink.js';

class FakeWritable implements WritableFileLike {
  bytes = new Uint8Array();
  writes: number[] = [];
  closed = false;
  aborted = false;
  async write(request: { type: 'write'; position: number; data: Uint8Array }): Promise<void> {
    const end = request.position + request.data.length;
    if (end > this.bytes.length) {
      const grown = new Uint8Array(end);
      grown.set(this.bytes);
      this.bytes = grown;
    }
    this.bytes.set(request.data, request.position);
    this.writes.push(request.data.length);
  }
  async close(): Promise<void> {
    this.closed = true;
  }
  async abort(): Promise<void> {
    this.aborted = true;
  }
}

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

function fakeStorage(writable: FakeWritable, available = 1 << 30) {
  const root = {
    getFileHandle: vi.fn(async () => ({ createWritable: vi.fn(async () => writable) })),
    removeEntry: vi.fn(async () => {}),
  };
  vi.stubGlobal('navigator', {
    storage: {
      estimate: vi.fn(async () => ({ quota: available, usage: 0 })),
      getDirectory: vi.fn(async () => root),
    },
  });
  return root;
}

function hasSignature(bytes: Uint8Array, signature: number): boolean {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let idx = 0; idx <= bytes.length - 4; idx++) {
    if (view.getUint32(idx, true) === signature) return true;
  }
  return false;
}

afterEach(() => vi.unstubAllGlobals());

describe('browser destinations', () => {
  it('streams a store-only ZIP with descriptors and a central directory', async () => {
    const writable = new FakeWritable();
    fakeStorage(writable);
    const destination = new ArchiveDestination();
    await destination.prepare(
      manifest([
        ['folder/a.bin', 3],
        ['folder/empty.txt', 0],
      ]),
    );

    const first = await destination.open(manifest([['folder/a.bin', 3]]).files[0]!);
    await first.write(0, new Uint8Array([1, 2]));
    await first.write(2, new Uint8Array([3]));
    await first.close();
    const second = await destination.open(manifest([['folder/empty.txt', 0]]).files[0]!);
    await second.close();
    await destination.close();

    const view = new DataView(writable.bytes.buffer);
    expect(view.getUint32(0, true)).toBe(0x04034b50);
    expect(view.getUint32(writable.bytes.length - 22, true)).toBe(0x06054b50);
    expect(hasSignature(writable.bytes, 0x02014b50)).toBe(true);
    expect(writable.closed).toBe(true);
    expect(Math.max(...writable.writes)).toBeLessThan(writable.bytes.length);
    expect(destination.result()).toMatchObject({ kind: 'opfs', name: 'folder.zip' });

    const dir = mkdtempSync(join(tmpdir(), 'sendbeam-zip-test-'));
    try {
      const path = join(dir, 'folder.zip');
      writeFileSync(path, writable.bytes);
      expect(execFileSync('unzip', ['-t', path], { encoding: 'utf8' })).toContain('No errors');
      expect(execFileSync('unzip', ['-p', path, 'folder/a.bin'])).toEqual(Buffer.from([1, 2, 3]));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses insufficient quota before opening OPFS', async () => {
    const writable = new FakeWritable();
    const root = fakeStorage(writable, 10);
    const destination = new ArchiveDestination();
    await expect(destination.prepare(manifest([['a.bin', 20]]))).rejects.toMatchObject({
      reason: 'quota',
    });
    expect(root.getFileHandle).not.toHaveBeenCalled();
  });

  it('writes a direct single-file destination without staging in memory', async () => {
    const writable = new FakeWritable();
    const handle = {
      createWritable: vi.fn(async () => writable),
    } as unknown as FileSystemFileHandle;
    const destination = createBrowserDestination({ kind: 'direct-file', handle });
    const one = manifest([['out.bin', 3]]);
    await destination.prepare(one);
    const sink = await destination.open(one.files[0]!);
    await sink.write(0, new Uint8Array([4, 5, 6]));
    await sink.close();
    await destination.close();
    expect(writable.bytes).toEqual(new Uint8Array([4, 5, 6]));
    expect(destination.result()).toEqual({ kind: 'direct' });
  });

  it('keeps an OPFS result alive until the UI explicitly cleans it up', async () => {
    const source = new File([new Uint8Array([7, 8, 9])], 'staged.bin');
    const removeEntry = vi.fn(async () => {});
    vi.stubGlobal('navigator', {
      storage: {
        getDirectory: vi.fn(async () => ({
          getFileHandle: vi.fn(async () => ({ getFile: vi.fn(async () => source) })),
          removeEntry,
        })),
      },
    });

    const result = await readOpfsOutput('staged-key', 'result.bin', 'application/octet-stream');
    expect(new Uint8Array(await result.arrayBuffer())).toEqual(new Uint8Array([7, 8, 9]));
    expect(removeEntry).not.toHaveBeenCalled();

    await removeOpfsOutput('staged-key');
    expect(removeEntry).toHaveBeenCalledWith('staged-key');
  });

  it('non-durable destinations never fail on credential attachment (BLOCKER 2)', async () => {
    const resumeRoot = new Uint8Array(32).fill(7);
    // direct-file + transferId: manifest setup succeeds and attach is a no-op.
    const fileWritable = new FakeWritable();
    const fileHandle = {
      createWritable: vi.fn(async () => fileWritable),
    } as unknown as FileSystemFileHandle;
    const fileDest = createBrowserDestination({ kind: 'direct-file', handle: fileHandle });
    const withId = (names: Array<[string, number]>) => ({
      ...manifest(names),
      transferId: 'a'.repeat(32),
    });
    await fileDest.prepare(withId([['out.bin', 3]]));
    await fileDest.attachResumeSecret?.(withId([['out.bin', 3]]), resumeRoot);

    // direct-directory + transferId: succeeds through manifest setup, attach is a no-op.
    const dirWritable = new FakeWritable();
    const dirRoot = {
      kind: 'directory',
      getDirectoryHandle: vi.fn(async () => ({
        kind: 'directory',
        getFileHandle: vi.fn(async () => ({ createWritable: vi.fn(async () => dirWritable) })),
        removeEntry: vi.fn(async () => {}),
      })),
      removeEntry: vi.fn(async () => {}),
    } as unknown as FileSystemDirectoryHandle;
    const dirDest = createBrowserDestination({ kind: 'direct-directory', handle: dirRoot });
    await dirDest.prepare(withId([['folder/out.bin', 3]]));
    await dirDest.attachResumeSecret?.(withId([['folder/out.bin', 3]]), resumeRoot);

    // Legacy single-file OPFS (no transferId): succeeds, attach is a no-op.
    const legacyWritable = new FakeWritable();
    const legacyRoot = fakeStorage(legacyWritable);
    const legacyDest = createBrowserDestination({ kind: 'auto' });
    await legacyDest.prepare(manifest([['plain.bin', 3]]));
    await legacyDest.attachResumeSecret?.(manifest([['plain.bin', 3]]), resumeRoot);
    expect(legacyRoot.getFileHandle).not.toHaveBeenCalled(); // no durable journal write path

    // Legacy archive fallback (no transferId, folders): succeeds, attach is a no-op.
    const archiveWritable = new FakeWritable();
    fakeStorage(archiveWritable);
    const archiveDest = createBrowserDestination({ kind: 'auto' });
    await archiveDest.prepare(manifest([['folder/a.bin', 3]]));
    await archiveDest.attachResumeSecret?.(manifest([['folder/a.bin', 3]]), resumeRoot);
  });
});

describe('handoff destination (V20-PR06)', () => {
  const handoffManifest = (contentKind: 'text' | 'link', body: Uint8Array): Manifest => ({
    type: FrameType.Manifest,
    transferId: 'handoff-test',
    contentKind,
    files: [
      {
        idx: 0,
        name: contentKind === 'text' ? 'text.txt' : 'link.txt',
        size: body.length,
        mime: 'text/plain; charset=utf-8',
        lastModified: 0,
        blockSize: 8,
        blocks: Math.ceil(body.length / 8),
        fileDigest: '00',
      },
    ],
    totalSize: body.length,
  });

  async function capture(contentKind: 'text' | 'link', body: Uint8Array) {
    const dest = new HandoffDestination(contentKind);
    await dest.prepare(handoffManifest(contentKind, body));
    const sink = await dest.open();
    await sink.write(0, body);
    await sink.close();
    await dest.close();
    return dest;
  }

  it('round-trips a valid text payload in memory', async () => {
    const body = new TextEncoder().encode('hello handoff');
    const dest = await capture('text', body);
    const out = dest.result();
    expect(out?.kind).toBe('handoff');
    if (out?.kind !== 'handoff') throw new Error('unreachable');
    expect(out.contentKind).toBe('text');
    expect(out.text).toBe('hello handoff');
  });

  it('rejects invalid UTF-8 payloads at result time', async () => {
    const dest = await capture('text', new Uint8Array([0x68, 0x69, 0xff]));
    expect(() => dest.result()).toThrow(/not valid UTF-8/);
  });

  it('rejects malformed link payloads at result time', async () => {
    for (const bad of [
      'javascript:alert(1)',
      'ftp://example.com/x',
      'not a url',
      'https://exam ple.com',
    ]) {
      const dest = await capture('link', new TextEncoder().encode(bad));
      expect(() => dest.result(), bad).toThrow(/handoff: link/);
    }
  });

  it('accepts a valid https link payload', async () => {
    const dest = await capture('link', new TextEncoder().encode('https://example.com/x'));
    const out = dest.result();
    expect(out?.kind).toBe('handoff');
  });

  it('exposes nothing before close', async () => {
    const dest = new HandoffDestination('text');
    const body = new TextEncoder().encode('hello');
    await dest.prepare(handoffManifest('text', body));
    const sink = await dest.open();
    await sink.write(0, body);
    expect(dest.result()).toBeUndefined();
  });

  it('close rejects a short write even when the bytes are valid UTF-8', async () => {
    const dest = new HandoffDestination('text');
    const body = new TextEncoder().encode('hello');
    await dest.prepare(handoffManifest('text', body));
    const sink = await dest.open();
    // A valid UTF-8 prefix that is shorter than the manifest size.
    await sink.write(0, new TextEncoder().encode('hel'));
    await expect(dest.close()).rejects.toThrow(/expected 5/);
  });

  it('createBrowserDestination routes handoff envelopes to memory, not disk', async () => {
    const body = new TextEncoder().encode('hello');
    const dest = createBrowserDestination({ kind: 'auto' });
    await dest.prepare(handoffManifest('text', body));
    // No disk-backed destination was created: the only write surface is the sink.
    const sink = await dest.open(handoffManifest('text', body).files[0]!);
    await sink.write(0, body);
    await sink.close();
    await dest.close();
    const out = dest.result?.();
    expect(out?.kind).toBe('handoff');
  });
});
