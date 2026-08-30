import { describe, it, expect } from 'vitest';
import { FRAME_FLAG_LAST_IN_BLOCK, FRAME_FLAG_PADDED, FRAME_VERSION } from './constants.js';
import { padBucketSize, padPayload, unpadPayload } from './frame.js';
import { open, openSequenced, sealPadded } from './aead.js';
import { FrameType } from './transfer.js';
import { deriveTransferKeys } from './keyschedule.js';
import { sha256 } from './webcrypto.js';
import { MemorySink, bytesSource } from './transfer-ports.js';
import { TransferSender } from './transfer-sender.js';
import { TransferReceiver } from './transfer-receiver.js';

describe('traffic padding', () => {
  it('computes correct power-of-two bucket sizes', () => {
    expect(padBucketSize(0)).toBe(256);
    expect(padBucketSize(1)).toBe(256);
    expect(padBucketSize(100)).toBe(256);
    expect(padBucketSize(254)).toBe(256);
    expect(padBucketSize(255)).toBe(512);
    expect(padBucketSize(510)).toBe(512);
    expect(padBucketSize(511)).toBe(1024);
    expect(padBucketSize(1000)).toBe(1024);
    expect(padBucketSize(1022)).toBe(1024);
    expect(padBucketSize(1023)).toBe(2048);
    expect(padBucketSize(4000)).toBe(4096);
    expect(padBucketSize(4094)).toBe(4096);
    expect(padBucketSize(4095)).toBe(8192);
    expect(padBucketSize(16382)).toBe(16384);
    expect(padBucketSize(16383)).toBe(32768);
    expect(padBucketSize(32766)).toBe(32768);
    expect(padBucketSize(32767)).toBe(65535);
    expect(padBucketSize(60000)).toBe(65535);
    expect(padBucketSize(65533)).toBe(65535);
  });

  it('pads and unpads payloads cleanly across multiple lengths', () => {
    const lengths = [0, 1, 10, 254, 255, 500, 1022, 1023, 4094, 16382, 32766, 65533];
    for (const len of lengths) {
      const payload = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        payload[i] = (i * 11 + 7) % 256;
      }

      const padded = padPayload(payload);
      expect(padded.length).toBe(padBucketSize(len));

      const unpadded = unpadPayload(padded);
      expect(unpadded).toEqual(payload);
    }
  });

  it('fails closed on malformed padding', () => {
    // 1. Truncated
    expect(() => unpadPayload(new Uint8Array([0]))).toThrow(/too short/);

    // 2. Length field exceeds buffer
    const badLen = new Uint8Array(256);
    new DataView(badLen.buffer).setUint16(0, 256, false); // needs 258 bytes
    expect(() => unpadPayload(badLen)).toThrow(/exceeds buffer/);

    // 3. Non-zero padding byte
    const badPad = new Uint8Array(256);
    new DataView(badPad.buffer).setUint16(0, 4, false);
    badPad.set(new Uint8Array([1, 2, 3, 4]), 2);
    badPad[100] = 0x01; // corrupted padding byte
    expect(() => unpadPayload(badPad)).toThrow(/non-zero padding byte/);
  });

  it('seals padded frames and recovers plaintext with open', async () => {
    const master = new Uint8Array(32).fill(0x42);
    const keys = await deriveTransferKeys(master);

    const payload = new TextEncoder().encode('Hello padded authenticated world!');
    const header = {
      version: FRAME_VERSION,
      type: FrameType.BlockData,
      flags: FRAME_FLAG_LAST_IN_BLOCK,
      fileIdx: 0,
      blockIdx: 1,
      frameOff: 0,
    };

    const sealed = await sealPadded(keys.o2j, 1, header, payload);
    const opened = await open(keys.o2j, 1, sealed);

    expect(opened.header.flags & FRAME_FLAG_PADDED).not.toBe(0);
    expect(opened.header.flags & FRAME_FLAG_LAST_IN_BLOCK).not.toBe(0);
    expect(opened.plaintext).toEqual(payload);

    // openSequenced also works
    const seqOpened = await openSequenced(keys.o2j, 1, sealed);
    expect(seqOpened.plaintext).toEqual(payload);
  });

  it('runs complete padded transfer between TransferSender and TransferReceiver', async () => {
    const master = new Uint8Array(32).fill(0x55);
    const keys = await deriveTransferKeys(master);

    const data = new Uint8Array(100 * 1024); // 100 KB
    for (let i = 0; i < data.length; i++) data[i] = (i * 13 + 17) % 256;

    const source = bytesSource(data, {
      name: 'padded-test.bin',
      size: data.length,
      mime: 'application/octet-stream',
      lastModified: 0,
    });
    const sink = new MemorySink();

    const networkQueue: Uint8Array[] = [];

    const sender = new TransferSender({
      file: source,
      send: (frame) => {
        networkQueue.push(frame);
        void deliverReceiver();
      },
      sendDir: keys.o2j,
      recvDir: keys.j2o,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: () => {
        let buf = new Uint8Array(0);
        return {
          update: (b) => {
            const next = new Uint8Array(buf.length + b.length);
            next.set(buf);
            next.set(b, buf.length);
            buf = next;
          },
          hexDigest: async () => {
            const hash = await sha256(buf);
            return Array.from(hash)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');
          },
        };
      },
      padding: true,
    });

    const receiver = new TransferReceiver({
      sink,
      send: (frame) => {
        void sender.handle(frame);
      },
      sendDir: keys.j2o,
      recvDir: keys.o2j,
      sendCounterStart: 0,
      recvCounterStart: 0,
      createDigest: () => {
        let buf = new Uint8Array(0);
        return {
          update: (b) => {
            const next = new Uint8Array(buf.length + b.length);
            next.set(buf);
            next.set(b, buf.length);
            buf = next;
          },
          hexDigest: async () => {
            const hash = await sha256(buf);
            return Array.from(hash)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');
          },
        };
      },
      padding: true,
    });

    let delivering = false;
    async function deliverReceiver() {
      if (delivering) return;
      delivering = true;
      try {
        while (networkQueue.length > 0) {
          const frame = networkQueue.shift()!;
          await receiver.handle(frame);
        }
      } finally {
        delivering = false;
      }
    }

    const [sendDigest, recvOutcome] = await Promise.all([sender.run(), receiver.done]);

    expect(sendDigest).toBe(recvOutcome.digest);
    expect(sink.bytes()).toEqual(data);
  });
});
