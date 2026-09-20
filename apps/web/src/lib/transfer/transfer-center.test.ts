import { describe, expect, it } from 'vitest';
import {
  humanBytes,
  isLiveState,
  isTerminalState,
  stateLabel,
  stateTone,
  visibleGroups,
} from './transfer-center.js';
import type { TransferCenterSnapshot } from '../wails/wails-adapter.js';

describe('transfer-center helpers', () => {
  it('labels every display state, including the uncertain verified window', () => {
    expect(stateLabel('verified')).toBe('Verified — awaiting save');
    expect(stateLabel('completed')).toBe('Delivered');
    expect(stateLabel('interrupted')).toBe('Interrupted');
    expect(stateLabel('broken')).toBe('Unreadable');
  });

  it('verified is informational, never shown as delivered', () => {
    expect(stateTone('verified')).toBe('info');
    expect(stateTone('completed')).toBe('ok');
    expect(isTerminalState('verified')).toBe(false);
    expect(isTerminalState('completed')).toBe(true);
  });

  it('live states accept cancel, terminal states accept forget', () => {
    for (const s of ['queued', 'active', 'interrupted', 'paused']) {
      expect(isLiveState(s)).toBe(true);
      expect(isTerminalState(s)).toBe(false);
    }
    for (const s of ['completed', 'failed', 'cancelled']) {
      expect(isTerminalState(s)).toBe(true);
      expect(isLiveState(s)).toBe(false);
    }
  });

  it('formats byte counts', () => {
    expect(humanBytes(0)).toBe('0 B');
    expect(humanBytes(1536)).toBe('1.5 KB');
    expect(humanBytes(5 * 1024 * 1024)).toBe('5.0 MB');
  });

  it('lists only non-empty groups in order', () => {
    const snap = {
      takenAt: '',
      groups: [
        { state: 'queued', jobs: [] },
        { state: 'active', jobs: [{ jobId: 'a' }] },
        { state: 'completed', jobs: [{ jobId: 'b' }, { jobId: 'c' }] },
      ],
      summary: { total: 3, byState: {}, broken: 0 },
    } as unknown as TransferCenterSnapshot;
    expect(visibleGroups(snap)).toEqual([
      { state: 'active', count: 1 },
      { state: 'completed', count: 2 },
    ]);
  });
});
