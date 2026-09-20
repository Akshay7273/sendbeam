import { describe, expect, it } from 'vitest';
import { FrameType, type Manifest, type Provenance } from './transfer.js';
import { validateManifest, validateProvenance } from './safe-path.js';
import { manifestFingerprint } from './journal.js';

const validProvenance = (): Provenance => ({
  routineId: '0123456789abcdef0123456789abcdef',
  routineName: 'nightly backup',
  senderLabel: 'akshay-laptop',
  trigger: 'watch',
});

const manifestWith = (provenance: Provenance | undefined): Manifest => ({
  type: FrameType.Manifest,
  ...(provenance !== undefined ? { provenance } : {}),
  files: [
    {
      idx: 0,
      name: 'a.bin',
      size: 10,
      mime: 'application/octet-stream',
      lastModified: 5,
      blockSize: 8,
      blocks: 2,
      fileDigest: 'ab',
    },
  ],
  totalSize: 10,
});

describe('validateProvenance', () => {
  it('accepts an absent provenance (an ordinary one-off send)', () => {
    expect(() => validateProvenance(undefined)).not.toThrow();
  });

  it('accepts a valid provenance', () => {
    expect(() => validateProvenance(validProvenance())).not.toThrow();
  });

  it.each(['manual', 'watch', 'schedule', 'retry'])('accepts trigger %j', (trigger) => {
    expect(() => validateProvenance({ ...validProvenance(), trigger })).not.toThrow();
  });

  it.each([
    ['short routine id', (p: Provenance) => ({ ...p, routineId: 'abc' })],
    [
      'uppercase routine id',
      (p: Provenance) => ({ ...p, routineId: '0123456789ABCDEF0123456789ABCDEF' }),
    ],
    [
      'non-hex routine id',
      (p: Provenance) => ({ ...p, routineId: '0123456789abcdeg0123456789abcdef' }),
    ],
    ['empty routine name', (p: Provenance) => ({ ...p, routineName: '' })],
    ['empty sender label', (p: Provenance) => ({ ...p, senderLabel: '' })],
    ['routine name too long', (p: Provenance) => ({ ...p, routineName: 'x'.repeat(257) })],
    ['sender label too long', (p: Provenance) => ({ ...p, senderLabel: 'x'.repeat(257) })],
    ['unknown trigger', (p: Provenance) => ({ ...p, trigger: 'cron' })],
  ])('rejects %s', (_name, mutate) => {
    expect(() => validateProvenance(mutate(validProvenance()))).toThrow();
  });
});

describe('validateManifest with provenance', () => {
  it('keeps a valid provenance in the canonical manifest, in Go key order', () => {
    const out = validateManifest(manifestWith(validProvenance()));
    expect(out.provenance).toEqual(validProvenance());
    const keys = Object.keys(JSON.parse(JSON.stringify(out)));
    expect(keys).toEqual(['type', 'provenance', 'files', 'totalSize']);
    expect(JSON.stringify(out)).toBe(
      '{"type":2,"provenance":{"routineId":"0123456789abcdef0123456789abcdef","routineName":"nightly backup","senderLabel":"akshay-laptop","trigger":"watch"},' +
        '"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}',
    );
  });

  it('leaves a provenance-free manifest untouched', () => {
    const out = validateManifest(manifestWith(undefined));
    expect(out.provenance).toBeUndefined();
    expect('provenance' in out).toBe(false);
  });

  it('fails closed on a malformed provenance', () => {
    expect(() =>
      validateManifest(manifestWith({ ...validProvenance(), routineId: 'nope' })),
    ).toThrow();
  });
});

describe('manifestFingerprint with provenance', () => {
  it('fingerprints identically with and without provenance (advisory label, not identity)', async () => {
    const plain = await manifestFingerprint(manifestWith(undefined));
    const labeled = await manifestFingerprint(manifestWith(validProvenance()));
    const other = await manifestFingerprint(
      manifestWith({
        routineId: 'ffffffffffffffffffffffffffffffff',
        routineName: 'other routine',
        senderLabel: 'other-device',
        trigger: 'schedule',
      }),
    );
    expect(labeled).toBe(plain);
    expect(other).toBe(plain);
  });

  it('still fails closed on a malformed provenance', async () => {
    await expect(
      manifestFingerprint(manifestWith({ ...validProvenance(), trigger: 'cron' })),
    ).rejects.toThrow();
  });
});
