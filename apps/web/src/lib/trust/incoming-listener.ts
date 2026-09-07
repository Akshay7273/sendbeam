/**
 * Browser incoming transfer listener and consent coordinator (V19-PR09).
 * Manages opaque rendezvous listener sockets in pure browser mode,
 * handles user consent prompts via IncomingTransferModal,
 * and bridges Wails v3 sendbeam:consent events in desktop mode.
 */

import {
  deriveRendezvousHandleForTime,
  formatFingerprint,
  getOrCreateBrowserIdentity,
  hexToBytes,
  type TrustRecord,
} from '@sendbeam/protocol';
import { getBrowserStores, isDesktopApp } from './devices.js';
import { getWailsBridge } from '../wails/wails-adapter.js';
import type { IncomingTransferRequest } from './types.js';
import { opaqueJoin, type OpaqueRendezvousController } from '../session/opaque-rendezvous.js';
import { runReceive, type TransferController, type TransferOutcome } from '../session/transfer.js';

export interface IncomingListenerOptions {
  serverUrl?: string;
  iceServers?: RTCIceServer[];
  onIncomingRequest?: (request: IncomingTransferRequest) => void;
  onTransferStart?: (transferId: string, controller: TransferController) => void;
  onTransferComplete?: (transferId: string, outcome: TransferOutcome) => void;
  onTransferError?: (transferId: string, err: Error) => void;
}

export class IncomingTransferCoordinator {
  private running = false;
  private readonly options: IncomingListenerOptions;
  private activeListeners = new Map<string, OpaqueRendezvousController>();
  private startingListeners = new Set<string>();
  private pendingConsents = new Map<string, (accepted: boolean) => void>();
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private desktopConsentCleanup: (() => void) | null = null;

  constructor(options: IncomingListenerOptions = {}) {
    this.options = options;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Desktop app delegates listening to native engine and receives events
    const bridge = getWailsBridge();
    if (bridge) {
      this.desktopConsentCleanup = bridge.events.on('sendbeam:consent', (data: unknown) => {
        this.handleDesktopConsentEvent(data);
      });
      return;
    }
    if (isDesktopApp() && typeof window !== 'undefined' && window.runtime?.EventsOn) {
      this.desktopConsentCleanup = window.runtime.EventsOn('sendbeam:consent', (data: unknown) => {
        this.handleDesktopConsentEvent(data);
      });
      return;
    }

    // Pure browser mode: listen on opaque rendezvous handles
    await this.refreshListeners();
    this.refreshTimer = setInterval(
      () => {
        void this.refreshListeners();
      },
      3 * 60 * 1000,
    ); // refresh every 3 minutes
  }

  stop(): void {
    this.running = false;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.desktopConsentCleanup) {
      this.desktopConsentCleanup();
      this.desktopConsentCleanup = null;
    }
    for (const ctrl of this.activeListeners.values()) {
      ctrl.cancel('listener stopped');
    }
    this.activeListeners.clear();
    this.startingListeners.clear();
    for (const resolve of this.pendingConsents.values()) {
      resolve(false);
    }
    this.pendingConsents.clear();
  }

  async respondConsent(transferId: string, accepted: boolean, reason?: string): Promise<void> {
    const bridge = getWailsBridge();
    if (bridge) {
      const decision = {
        accepted,
        ...(reason ? { reason } : {}),
      };
      await bridge.transfer.respondConsent(transferId, decision);
      return;
    }
    if (isDesktopApp() && window.go?.engine?.TransferService?.RespondConsent) {
      const decision = {
        accepted,
        ...(reason ? { reason } : {}),
      };
      await window.go.engine.TransferService.RespondConsent(transferId, decision);
      return;
    }

    const resolver = this.pendingConsents.get(transferId);
    if (resolver) {
      this.pendingConsents.delete(transferId);
      resolver(accepted);
    }
  }

  private handleDesktopConsentEvent(data: unknown): void {
    if (!data || typeof data !== 'object') return;
    const req = data as Record<string, unknown>;
    const transferId = String(req['transferId'] || '');
    const peerDeviceId = String(req['peerDeviceId'] || '');
    const peerLabel = String(req['peerLabel'] || peerDeviceId);
    const totalSize = Number(req['totalSize'] || 0);

    let files: Array<{ name: string; size: number }> = [];
    if (Array.isArray(req['files'])) {
      files = req['files'].map((f: Record<string, unknown>) => ({
        name: String(f['name'] || ''),
        size: Number(f['size'] || 0),
      }));
    }

    const incomingReq: IncomingTransferRequest = {
      transferId,
      senderDeviceId: peerDeviceId,
      senderLabel: peerLabel,
      senderFingerprint: peerDeviceId.slice(0, 16),
      fileCount: files.length > 0 ? files.length : 1,
      totalBytes: totalSize,
      files,
    };

    this.options.onIncomingRequest?.(incomingReq);
  }

  private async refreshListeners(): Promise<void> {
    if (!this.running) return;

    try {
      const { trustStore, secretStore, tombstoneStore } = getBrowserStores();
      const devices = await trustStore.listDevices();
      const localId = await getOrCreateBrowserIdentity();

      const activeDevIds = new Set<string>();

      for (const dev of devices) {
        if (dev.revoked) continue;
        if (tombstoneStore && (await tombstoneStore.hasTombstone(dev.deviceId))) continue;

        const kPair = await secretStore?.resolvePairSecret(dev.deviceId, dev.pairCredentialRef);
        if (!kPair || kPair.length === 0) continue;

        activeDevIds.add(dev.deviceId);

        if (!this.activeListeners.has(dev.deviceId) && !this.startingListeners.has(dev.deviceId)) {
          await this.startListeningForDevice(dev, kPair, localId);
        }
      }

      // Prune listeners for devices no longer active
      for (const [id, ctrl] of this.activeListeners.entries()) {
        if (!activeDevIds.has(id)) {
          ctrl.cancel('device unshared or revoked');
          this.activeListeners.delete(id);
        }
      }
    } catch {
      // Ignored; retry on next tick
    }
  }

  private async startListeningForDevice(
    dev: TrustRecord,
    kPair: Uint8Array,
    localId: import('@sendbeam/protocol').DeviceIdentity,
  ): Promise<void> {
    this.startingListeners.add(dev.deviceId);
    try {
      const handle = await deriveRendezvousHandleForTime(kPair);
      if (!this.running) return;
      const peerPublicKey = hexToBytes(dev.publicKey);

      let fp = '';
      try {
        fp = formatFingerprint(peerPublicKey);
      } catch {
        fp = dev.deviceId.slice(0, 16);
      }

      const ctrl = opaqueJoin({
        ...(this.options.serverUrl ? { url: this.options.serverUrl } : {}),
        handle,
        localIdentity: localId,
        peerDeviceId: dev.deviceId,
        peerPublicKey,
        kPair,
        pairCredentialRef: dev.pairCredentialRef,
        localCapabilities: ['sendbeam/3', 'transfer.v1', 'padding'],
      });

      this.activeListeners.set(dev.deviceId, ctrl);
      void this.handleIncomingLoop(dev, kPair, localId, ctrl, fp);
    } finally {
      this.startingListeners.delete(dev.deviceId);
    }
  }

  private async handleIncomingLoop(
    dev: TrustRecord,
    kPair: Uint8Array,
    localId: import('@sendbeam/protocol').DeviceIdentity,
    ctrl: OpaqueRendezvousController,
    fp: string,
  ): Promise<void> {
    try {
      const res = await ctrl.done;
      this.activeListeners.delete(dev.deviceId);

      // Successfully handshaked with sender! Adopt channel and prepare transfer
      const signaling = ctrl.adoptSignaling();

      const transferId = `transfer-${Date.now()}`;
      const consentRequired = !dev.policy?.autoAccept;

      const consentPromise = new Promise<boolean>((resolve) => {
        if (!consentRequired) {
          resolve(true);
        } else {
          this.pendingConsents.set(transferId, resolve);
        }
      });

      const transferCtrl = runReceive(
        res,
        signaling,
        { kind: 'auto' },
        {
          requirePadding: dev.policy?.requirePadding ?? false,
          ...(this.options.iceServers ? { iceServers: this.options.iceServers } : {}),
          onConsent: async (manifest) => {
            if (!consentRequired) {
              return true;
            }

            this.options.onIncomingRequest?.({
              transferId,
              senderDeviceId: dev.deviceId,
              senderLabel: dev.localLabel,
              senderFingerprint: fp,
              fileCount: manifest.files.length,
              totalBytes: manifest.totalSize,
              files: manifest.files.map((f) => ({ name: f.name, size: f.size })),
            });

            return await consentPromise;
          },
        },
      );

      this.options.onTransferStart?.(transferId, transferCtrl);

      try {
        const outcome = await transferCtrl.done;
        this.options.onTransferComplete?.(transferId, outcome);
      } catch (err: unknown) {
        this.options.onTransferError?.(
          transferId,
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    } catch {
      this.activeListeners.delete(dev.deviceId);
    } finally {
      // If still running, restart listener for this device
      if (this.running) {
        setTimeout(() => {
          if (
            this.running &&
            !this.activeListeners.has(dev.deviceId) &&
            !this.startingListeners.has(dev.deviceId)
          ) {
            void this.startListeningForDevice(dev, kPair, localId);
          }
        }, 1000);
      }
    }
  }
}
