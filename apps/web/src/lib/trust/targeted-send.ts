/**
 * Browser targeted send and multi-send delivery (V19-PR09).
 * Implements peer identity binding, bounded dial/transfer concurrency,
 * and independent partial failure isolation matching Go packages/engine/transfer/broadcast.go.
 */

import {
  type DeviceIdentity,
  type TrustRecord,
  deriveRendezvousHandleForTime,
  getOrCreateBrowserIdentity,
  hexToBytes,
} from '@sendbeam/protocol';
import { getBrowserStores } from './devices.js';
import type { BroadcastDeviceState, BroadcastDeviceStatus, TrustedDeviceUI } from './types.js';
import { opaqueOffer } from '../session/opaque-rendezvous.js';
import { runSend, type TransferController, type TransferOutcome } from '../session/transfer.js';

export interface ResolvedPeerTarget {
  record: TrustRecord;
  kPair: Uint8Array;
  peerPublicKey: Uint8Array;
  handle: string;
}

export async function resolveTargetPeer(deviceId: string): Promise<ResolvedPeerTarget> {
  const { trustStore, secretStore, tombstoneStore } = getBrowserStores();

  const dev = await trustStore.getDevice(deviceId);
  if (!dev) {
    throw new Error(`Target device not found in trust store: ${deviceId}`);
  }

  if (dev.revoked) {
    throw new Error(`Trust for device "${dev.localLabel}" is revoked`);
  }

  if (tombstoneStore && (await tombstoneStore.hasTombstone(deviceId))) {
    throw new Error(`Trust for device "${dev.localLabel}" is revoked by tombstone`);
  }

  const kPair = await secretStore?.resolvePairSecret(dev.deviceId, dev.pairCredentialRef);
  if (!kPair || kPair.length === 0) {
    throw new Error(`Pairing secret missing for device "${dev.localLabel}"`);
  }

  const peerPublicKey = hexToBytes(dev.publicKey);
  const handle = await deriveRendezvousHandleForTime(kPair);

  return {
    record: dev,
    kPair,
    peerPublicKey,
    handle,
  };
}

export function classifyBroadcastError(err: unknown): {
  status: BroadcastDeviceStatus;
  message: string;
} {
  const raw = err instanceof Error ? err.message : String(err);
  const lower = raw.toLowerCase();

  if (
    lower.includes('refused') ||
    lower.includes('declined') ||
    lower.includes('rejected') ||
    lower.includes('canceled') ||
    lower.includes('cancelled') ||
    lower.includes('revoked')
  ) {
    return { status: 'refused', message: raw };
  }

  if (
    lower.includes('offline') ||
    lower.includes('unreachable') ||
    lower.includes('timeout') ||
    lower.includes('deadline exceeded') ||
    lower.includes('peer not found') ||
    lower.includes('closed')
  ) {
    return { status: 'offline', message: raw };
  }

  return { status: 'failed', message: raw };
}

export interface TargetedSendOptions {
  target: TrustedDeviceUI;
  files: File[];
  serverUrl?: string;
  iceServers?: RTCIceServer[];
  timeoutMs?: number;
  localIdentity?: DeviceIdentity;
  onProgress?: (bytes: number) => void;
  onStateChange?: (status: BroadcastDeviceStatus) => void;
}

export interface TargetedSendSession {
  readonly target: TrustedDeviceUI;
  readonly transferCtrl: TransferController;
  readonly done: Promise<TransferOutcome>;
  cancel(reason?: string): void;
}

export async function startTargetedSend(opts: TargetedSendOptions): Promise<TargetedSendSession> {
  const localId = opts.localIdentity ?? (await getOrCreateBrowserIdentity());
  const peer = await resolveTargetPeer(opts.target.deviceId);

  opts.onStateChange?.('connecting');

  const rendezvousCtrl = opaqueOffer({
    ...(opts.serverUrl ? { url: opts.serverUrl } : {}),
    handle: peer.handle,
    localIdentity: localId,
    peerDeviceId: peer.record.deviceId,
    peerPublicKey: peer.peerPublicKey,
    kPair: peer.kPair,
    pairCredentialRef: peer.record.pairCredentialRef,
    localCapabilities: ['sendbeam/3', 'transfer.v1', 'padding'],
    timeoutMs: opts.timeoutMs ?? 45_000,
  });

  let canceled = false;
  let activeTransfer: TransferController | null = null;

  const donePromise = (async (): Promise<TransferOutcome> => {
    try {
      const res = await rendezvousCtrl.done;
      if (canceled) {
        throw new Error('transfer cancelled');
      }

      const signaling = rendezvousCtrl.adoptSignaling();
      opts.onStateChange?.('sending');

      const ctrl = runSend(res, signaling, {
        files: opts.files,
        requirePadding: peer.record.policy?.requirePadding ?? false,
        ...(opts.iceServers ? { iceServers: opts.iceServers } : {}),
      });
      activeTransfer = ctrl;

      return await ctrl.done;
    } catch (err: unknown) {
      rendezvousCtrl.cancel();
      activeTransfer?.cancel();
      throw err;
    }
  })();

  return {
    target: opts.target,
    get transferCtrl() {
      if (!activeTransfer) {
        throw new Error('transfer not yet started');
      }
      return activeTransfer;
    },
    done: donePromise,
    cancel: (reason = 'cancelled') => {
      canceled = true;
      rendezvousCtrl.cancel(reason);
      activeTransfer?.cancel(reason);
    },
  };
}

export interface BroadcastSendOptions {
  serverUrl?: string;
  iceServers?: RTCIceServer[];
  concurrency?: number;
  timeoutMs?: number;
  localIdentity?: DeviceIdentity;
  onTargetUpdate?: (state: BroadcastDeviceState) => void;
}

export interface BroadcastSendResult {
  allOk: boolean;
  results: BroadcastDeviceState[];
}

export async function runBroadcastSend(
  targets: TrustedDeviceUI[],
  files: File[],
  opts: BroadcastSendOptions = {},
): Promise<BroadcastSendResult> {
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);

  const states = new Map<string, BroadcastDeviceState>();
  for (const t of targets) {
    const s: BroadcastDeviceState = {
      deviceId: t.deviceId,
      label: t.localLabel,
      status: 'pending',
      progressBytes: 0,
      totalBytes,
    };
    states.set(t.deviceId, s);
    opts.onTargetUpdate?.({ ...s });
  }

  const updateState = (deviceId: string, patch: Partial<BroadcastDeviceState>) => {
    const curr = states.get(deviceId);
    if (!curr) return;
    const updated = { ...curr, ...patch };
    states.set(deviceId, updated);
    opts.onTargetUpdate?.({ ...updated });
  };

  const concurrency = Math.max(1, Math.min(opts.concurrency ?? 4, targets.length));
  let running = 0;
  let queueIndex = 0;

  const localId = opts.localIdentity ?? (await getOrCreateBrowserIdentity());

  const processTarget = async (target: TrustedDeviceUI): Promise<void> => {
    const start = Date.now();
    try {
      updateState(target.deviceId, { status: 'connecting' });

      let peer: ResolvedPeerTarget;
      try {
        peer = await resolveTargetPeer(target.deviceId);
      } catch (err: unknown) {
        const classified = classifyBroadcastError(err);
        updateState(target.deviceId, {
          status: classified.status,
          durationMs: Date.now() - start,
          error: classified.message,
        });
        return;
      }

      const rendezvousCtrl = opaqueOffer({
        ...(opts.serverUrl ? { url: opts.serverUrl } : {}),
        handle: peer.handle,
        localIdentity: localId,
        peerDeviceId: peer.record.deviceId,
        peerPublicKey: peer.peerPublicKey,
        kPair: peer.kPair,
        pairCredentialRef: peer.record.pairCredentialRef,
        localCapabilities: ['sendbeam/3', 'transfer.v1', 'padding'],
        timeoutMs: opts.timeoutMs ?? 45_000,
      });

      const res = await rendezvousCtrl.done;
      const signaling = rendezvousCtrl.adoptSignaling();

      updateState(target.deviceId, { status: 'sending' });

      const transferCtrl = runSend(res, signaling, {
        files,
        requirePadding: peer.record.policy?.requirePadding ?? false,
        ...(opts.iceServers ? { iceServers: opts.iceServers } : {}),
      });

      // Poll progress while active
      const progressTimer = setInterval(() => {
        const p = transferCtrl.progress();
        updateState(target.deviceId, { progressBytes: p });
      }, 150);

      try {
        const outcome = await transferCtrl.done;
        clearInterval(progressTimer);
        updateState(target.deviceId, {
          status: 'ok',
          progressBytes: totalBytes,
          durationMs: Date.now() - start,
          digest: outcome.digest,
        });
      } catch (transferErr: unknown) {
        clearInterval(progressTimer);
        const classified = classifyBroadcastError(transferErr);
        updateState(target.deviceId, {
          status: classified.status,
          durationMs: Date.now() - start,
          error: classified.message,
        });
      }
    } catch (err: unknown) {
      const classified = classifyBroadcastError(err);
      updateState(target.deviceId, {
        status: classified.status,
        durationMs: Date.now() - start,
        error: classified.message,
      });
    }
  };

  await new Promise<void>((resolve) => {
    if (targets.length === 0) {
      resolve();
      return;
    }

    const next = () => {
      if (queueIndex >= targets.length && running === 0) {
        resolve();
        return;
      }

      while (running < concurrency && queueIndex < targets.length) {
        const target = targets[queueIndex++];
        if (!target) break;
        running++;
        void processTarget(target).finally(() => {
          running--;
          next();
        });
      }
    };

    next();
  });

  const finalResults = targets.map((t) => states.get(t.deviceId)!);
  const allOk = finalResults.every((r) => r.status === 'ok');

  return {
    allOk,
    results: finalResults,
  };
}
