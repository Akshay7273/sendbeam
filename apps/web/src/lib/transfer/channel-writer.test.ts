import { describe, it, expect } from 'vitest';
import { ChannelWriter, type ChannelLike } from './channel-writer.js';

class FakeChannel implements ChannelLike {
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  onbufferedamountlow: ((ev: Event) => unknown) | null = null;
  sent: number[] = [];
  send(data: ArrayBuffer): void {
    this.sent.push(data.byteLength);
    this.bufferedAmount += data.byteLength;
  }
  /** Simulate the SCTP buffer draining below the low watermark. */
  drainTo(n: number): void {
    this.bufferedAmount = n;
    if (n <= this.bufferedAmountLowThreshold && this.onbufferedamountlow) {
      this.onbufferedamountlow.call(this, new Event('bufferedamountlow'));
    }
  }
}

describe('ChannelWriter', () => {
  it('sends immediately while under the high watermark', () => {
    const ch = new FakeChannel();
    const w = new ChannelWriter(ch);
    w.write(new ArrayBuffer(1000));
    expect(ch.sent).toEqual([1000]);
    expect(w.pending).toBe(0);
  });

  it('queues once bufferedAmount crosses the high watermark and drains on low', () => {
    const ch = new FakeChannel();
    const w = new ChannelWriter(ch);
    ch.bufferedAmount = 9 * 1024 * 1024; // above 8 MiB high watermark
    w.write(new ArrayBuffer(100));
    w.write(new ArrayBuffer(200));
    expect(ch.sent).toEqual([]);
    expect(w.pending).toBe(2);
    ch.drainTo(0);
    expect(ch.sent).toEqual([100, 200]);
    expect(w.pending).toBe(0);
  });

  it('preserves FIFO order once queuing has begun, even below the watermark', () => {
    const ch = new FakeChannel();
    const w = new ChannelWriter(ch);
    ch.bufferedAmount = 9 * 1024 * 1024;
    w.write(new ArrayBuffer(1)); // queued (over watermark)
    ch.bufferedAmount = 0; // drops without firing the low event
    w.write(new ArrayBuffer(2)); // must queue behind the first, not jump ahead
    expect(ch.sent).toEqual([]);
    expect(w.pending).toBe(2);
    ch.drainTo(0);
    expect(ch.sent).toEqual([1, 2]);
  });

  it('sets the low-watermark threshold on the channel', () => {
    const ch = new FakeChannel();
    new ChannelWriter(ch);
    expect(ch.bufferedAmountLowThreshold).toBe(1 * 1024 * 1024);
  });

  it('waits for buffered bytes to drain before graceful teardown', async () => {
    const ch = new FakeChannel();
    const writer = new ChannelWriter(ch);
    writer.write(new ArrayBuffer(100));
    setTimeout(() => ch.drainTo(0), 5);
    await writer.drain(100);
    expect(ch.bufferedAmount).toBe(0);
    expect(writer.pending).toBe(0);
    writer.dispose();
  });

  it('recovers from missed bufferedamountlow event on WebKit via safety drain timer', async () => {
    const ch = new FakeChannel();
    const writer = new ChannelWriter(ch);
    ch.bufferedAmount = 9 * 1024 * 1024;
    writer.write(new ArrayBuffer(50));
    expect(writer.pending).toBe(1);

    // Buffer drains, but WebKit never dispatches onbufferedamountlow event
    ch.bufferedAmount = 0;
    expect(ch.sent).toEqual([]);

    // Safety drain timer fires and drains the queue
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(ch.sent).toEqual([50]);
    expect(writer.pending).toBe(0);
    writer.dispose();
  });

  it('handles restricted channel without throwing when threshold setting fails', () => {
    const ch: ChannelLike = {
      bufferedAmount: 0,
      get bufferedAmountLowThreshold() {
        return 0;
      },
      set bufferedAmountLowThreshold(_val: number) {
        throw new Error('NotSupportedError');
      },
      send: () => {},
      onbufferedamountlow: null,
    };
    expect(() => new ChannelWriter(ch)).not.toThrow();
  });
});
