// Pure helpers for the Transfer Center screen (V20-PR03). Kept free of
// Svelte and Wails so they are unit-testable.
import type { TransferCenterSnapshot } from '../wails/wails-adapter.js';

/** Human label for a transfer-center display state. */
export function stateLabel(state: string): string {
  switch (state) {
    case 'queued':
      return 'Queued';
    case 'active':
      return 'Sending';
    case 'interrupted':
      return 'Interrupted';
    case 'verified':
      return 'Verified — awaiting save';
    case 'completed':
      return 'Delivered';
    case 'failed':
      return 'Failed';
    case 'cancelled':
      return 'Cancelled';
    case 'paused':
      return 'Paused';
    case 'draft':
      return 'Draft';
    case 'broken':
      return 'Unreadable';
    default:
      return state;
  }
}

/** Visual tone for a display state. */
export function stateTone(state: string): 'ok' | 'warn' | 'bad' | 'info' | 'muted' {
  switch (state) {
    case 'completed':
      return 'ok';
    case 'interrupted':
    case 'paused':
      return 'warn';
    case 'failed':
    case 'broken':
      return 'bad';
    case 'active':
    case 'verified':
      return 'info';
    default:
      return 'muted';
  }
}

/** Whether the job accepts operator actions (cancel / retry). */
export function isLiveState(state: string): boolean {
  return state === 'queued' || state === 'active' || state === 'interrupted' || state === 'paused';
}

/** Whether the job is terminal and may be forgotten / pruned. */
export function isTerminalState(state: string): boolean {
  return state === 'completed' || state === 'failed' || state === 'cancelled';
}

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[u]}`;
}

/** Non-empty state groups in snapshot order, for rendering. */
export function visibleGroups(snap: TransferCenterSnapshot): { state: string; count: number }[] {
  return snap.groups
    .filter((g) => g.jobs.length > 0)
    .map((g) => ({ state: g.state, count: g.jobs.length }));
}
