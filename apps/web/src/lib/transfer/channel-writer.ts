/**
 * Best-effort SCTP-buffer guard over an RTCDataChannel. The worker's in-flight window is the real
 * memory bound; this only keeps `bufferedAmount` from ballooning: queue while above the high
 * watermark, flush in order when the channel signals it has drained below the low watermark.
 *
 * Hardened for WebKit/Safari DataChannel quirks: sets bufferedAmountLowThreshold defensively,
 * listens via both property and addEventListener, and arms a safety drain timer so missed
 * or coalesced low-watermark events on WebKit cannot stall transfer draining.
 */

import { BUFFERED_AMOUNT_HIGH, BUFFERED_AMOUNT_LOW } from '@sendbeam/protocol';

export interface ChannelLike {
  bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  send(data: ArrayBuffer): void;
  onbufferedamountlow: ((ev: Event) => unknown) | null;
  addEventListener?(type: string, listener: (ev: Event) => unknown): void;
  removeEventListener?(type: string, listener: (ev: Event) => unknown): void;
}

export class ChannelWriter {
  private queue: ArrayBuffer[] = [];
  private safetyTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly onLow: (ev: Event) => void;

  constructor(private readonly channel: ChannelLike) {
    try {
      this.channel.bufferedAmountLowThreshold = BUFFERED_AMOUNT_LOW;
    } catch {
      // Best-effort property write for constrained or mock channels
    }
    this.onLow = () => this.flush();
    this.channel.onbufferedamountlow = this.onLow;
    if (typeof this.channel.addEventListener === 'function') {
      try {
        this.channel.addEventListener('bufferedamountlow', this.onLow);
      } catch {
        // Fall back to onbufferedamountlow
      }
    }
  }

  get pending(): number {
    return this.queue.length;
  }

  write(frame: ArrayBuffer): void {
    // Once anything is queued, everything queues behind it — FIFO holds even if bufferedAmount
    // has since dipped, since the low-watermark event is what authorises a drain.
    if (this.queue.length === 0 && this.channel.bufferedAmount < BUFFERED_AMOUNT_HIGH) {
      this.channel.send(frame);
    } else {
      this.queue.push(frame);
      this.armSafetyDrain();
    }
  }

  /** Wait briefly for queued and SCTP-buffered bytes to drain before graceful teardown. */
  async drain(timeoutMs = 500): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while ((this.queue.length > 0 || this.channel.bufferedAmount > 0) && Date.now() < deadline) {
      this.flush();
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  /** Teardown listeners and safety drain timers. */
  dispose(): void {
    if (this.safetyTimer !== undefined) {
      clearTimeout(this.safetyTimer);
      this.safetyTimer = undefined;
    }
    if (this.channel.onbufferedamountlow === this.onLow) {
      this.channel.onbufferedamountlow = null;
    }
    if (typeof this.channel.removeEventListener === 'function') {
      try {
        this.channel.removeEventListener('bufferedamountlow', this.onLow);
      } catch {
        // Ignore teardown errors
      }
    }
  }

  private armSafetyDrain(): void {
    if (this.safetyTimer !== undefined) return;
    this.safetyTimer = setTimeout(() => {
      this.safetyTimer = undefined;
      if (this.queue.length > 0) {
        this.flush();
        if (this.queue.length > 0) {
          this.armSafetyDrain();
        }
      }
    }, 50);
  }

  private flush(): void {
    while (this.queue.length > 0 && this.channel.bufferedAmount < BUFFERED_AMOUNT_HIGH) {
      const next = this.queue.shift()!;
      this.channel.send(next);
    }
    if (this.queue.length === 0 && this.safetyTimer !== undefined) {
      clearTimeout(this.safetyTimer);
      this.safetyTimer = undefined;
    }
  }
}
