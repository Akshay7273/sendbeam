import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes, bytesToHex } from './bytes.js';
import { padBucketSize, padPayload, unpadPayload } from './frame.js';
import { open, sealPadded } from './aead.js';
import { FRAME_FLAG_PADDED } from './constants.js';

interface PaddingVector {
  name: string;
  plaintext_hex: string;
  unpadded_len: number;
  bucket_size: number;
  padded_hex: string;
  key_hex: string;
  salt_hex: string;
  counter: number;
  header: {
    Version: number;
    Type: number;
    Flags: number;
    FileIdx: number;
    BlockIdx: number;
    FrameOff: number;
    Len: number;
  };
  sealed_hex: string;
  valid: boolean;
  expected_error?: string;
}

function loadPaddingVectors(): PaddingVector[] {
  const url = new URL('../../wire/testdata/padding-vectors.json', import.meta.url);
  return JSON.parse(readFileSync(fileURLToPath(url), 'utf8')) as PaddingVector[];
}

describe('padding vectors cross-feed', () => {
  const vectors = loadPaddingVectors();

  for (const v of vectors) {
    it(`verifies vector: ${v.name}`, async () => {
      const plaintext = hexToBytes(v.plaintext_hex);
      const key = hexToBytes(v.key_hex);
      const salt = hexToBytes(v.salt_hex);
      const dir = { key, salt };

      if (!v.valid) {
        if (v.padded_hex) {
          const padded = hexToBytes(v.padded_hex);
          expect(() => unpadPayload(padded)).toThrow();
        }
        if (v.sealed_hex) {
          const sealed = hexToBytes(v.sealed_hex);
          await expect(open(dir, v.counter, sealed)).rejects.toThrow();
        }
        return;
      }

      // 1. Bucket size computation
      expect(padBucketSize(plaintext.length)).toBe(v.bucket_size);

      // 2. Padding encoding
      const padded = padPayload(plaintext);
      expect(bytesToHex(padded)).toBe(v.padded_hex);

      // 3. Padding decoding
      const unpadded = unpadPayload(padded);
      expect(bytesToHex(unpadded)).toBe(v.plaintext_hex);

      // 4. Sealing
      const headerInput = {
        version: v.header.Version,
        type: v.header.Type,
        flags: v.header.Flags & ~FRAME_FLAG_PADDED,
        fileIdx: v.header.FileIdx,
        blockIdx: v.header.BlockIdx,
        frameOff: v.header.FrameOff,
      };
      const sealed = await sealPadded(dir, v.counter, headerInput, plaintext);
      expect(bytesToHex(sealed)).toBe(v.sealed_hex);

      // 5. Opening
      const opened = await open(dir, v.counter, sealed);
      expect(bytesToHex(opened.plaintext)).toBe(v.plaintext_hex);
      expect(opened.header.flags & FRAME_FLAG_PADDED).not.toBe(0);
    });
  }
});
