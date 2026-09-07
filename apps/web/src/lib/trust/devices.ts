import {
  type TrustPolicy,
  type TrustRecord,
  type TrustStore,
  type TombstoneStore,
  IndexedDBTrustStore,
  IndexedDBSecretStore,
  IndexedDBTombstoneStore,
  MemoryTrustStore,
  MemoryTombstoneStore,
  formatFingerprint,
  hexToBytes,
  isPersistentTrustSupported,
  PairingCoordinator,
  type PairingSessionConfig,
  type PairingTransport,
  type PairingMessage,
  MSG_PAIRING_REQUEST,
  MSG_PAIRING_RESPONSE,
  MSG_PAIRING_CONFIRM,
  getOrCreateBrowserIdentity,
  validateDeviceId,
  signRevocation,
  MemorySecretResolver,
  type SignalMsg,
} from '@sendbeam/protocol';
import { join, offer } from '../session/rendezvous.js';
import type { TrustedDeviceUI } from './types.js';

declare global {
  interface Window {
    go?: {
      engine?: {
        DeviceService?: {
          ListTrustedDevices(): Promise<TrustedDeviceUI[]>;
          RenameDevice(deviceId: string, newLabel: string): Promise<void>;
          UpdateDevicePolicy(deviceId: string, policy: TrustPolicy): Promise<void>;
          UnpairDevice(deviceId: string, purge: boolean): Promise<void>;
          PairDevice(
            server: string,
            code: string,
            name: string,
            autoAccept: boolean,
            dest: string,
          ): Promise<TrustedDeviceUI>;
        };
      };
    };
    runtime?: {
      EventsOn(eventName: string, callback: (data: unknown) => void): () => void;
    };
  }
}

export { isPersistentTrustSupported };

export function isDesktopApp(): boolean {
  return typeof window !== 'undefined' && !!window.go?.engine?.DeviceService;
}

type BrowserSecretStore = IndexedDBSecretStore | MemorySecretResolver;

// Browser storage instances
let browserTrustStore: TrustStore | null = null;
let browserSecretStore: BrowserSecretStore | null = null;
let browserTombstoneStore: TombstoneStore | null = null;

export function resetBrowserStoresForTesting(
  trustStore?: TrustStore,
  secretStore?: BrowserSecretStore,
  tombstoneStore?: TombstoneStore,
): void {
  browserTrustStore = trustStore ?? null;
  browserSecretStore = secretStore ?? null;
  browserTombstoneStore = tombstoneStore ?? null;
}

export function getBrowserStores(): {
  trustStore: TrustStore;
  secretStore: BrowserSecretStore | null;
  tombstoneStore: TombstoneStore;
} {
  if (!browserTrustStore) {
    if (typeof indexedDB !== 'undefined') {
      browserTrustStore = new IndexedDBTrustStore();
      browserSecretStore = new IndexedDBSecretStore();
      browserTombstoneStore = new IndexedDBTombstoneStore();
    } else {
      browserTrustStore = new MemoryTrustStore();
      browserTombstoneStore = new MemoryTombstoneStore();
    }
  }
  return {
    trustStore: browserTrustStore,
    secretStore: browserSecretStore,
    tombstoneStore: browserTombstoneStore ?? new MemoryTombstoneStore(),
  };
}

export async function listTrustedDevices(): Promise<TrustedDeviceUI[]> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.ListTrustedDevices();
  }

  const { trustStore } = getBrowserStores();
  const records = await trustStore.listDevices();
  const now = Date.now();

  return records.map((r: TrustRecord) => {
    let status: TrustedDeviceUI['status'] = 'offline';
    if (r.revoked) {
      status = 'revoked';
    } else {
      const seenTime = r.lastSeenAt ? new Date(r.lastSeenAt).getTime() : 0;
      if (now - seenTime < 15 * 60 * 1000) {
        status = 'online';
      }
    }

    let fp = '';
    try {
      fp = formatFingerprint(hexToBytes(r.publicKey));
    } catch {
      fp = r.deviceId.slice(0, 16);
    }

    const dev: TrustedDeviceUI = {
      deviceId: r.deviceId,
      localLabel: r.localLabel,
      fingerprint: fp,
      publicKey: r.publicKey,
      status,
      revoked: r.revoked,
      lastSeenAt: r.lastSeenAt || 'never',
      firstSeenAt: r.firstSeenAt,
      capabilities: r.capabilities || [],
      policy: r.policy || { autoAccept: false },
    };
    if (r.revokedBy !== undefined) dev.revokedBy = r.revokedBy;
    if (r.revocationSeq !== undefined) dev.revocationSeq = r.revocationSeq;
    return dev;
  });
}

export async function renameTrustedDevice(deviceId: string, newLabel: string): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.RenameDevice(deviceId, newLabel);
  }

  const { trustStore } = getBrowserStores();
  const rec = await trustStore.getDevice(deviceId);
  if (!rec) throw new Error('device not found');
  rec.localLabel = newLabel.trim();
  await trustStore.addOrUpdateDevice(rec);
}

export async function updateTrustedDevicePolicy(
  deviceId: string,
  policy: TrustPolicy,
): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UpdateDevicePolicy(deviceId, policy);
  }

  const { trustStore } = getBrowserStores();
  await trustStore.updatePolicy(deviceId, policy);
}

export async function unpairTrustedDevice(deviceId: string, purge: boolean): Promise<void> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.UnpairDevice(deviceId, purge);
  }

  const { trustStore, secretStore, tombstoneStore } = getBrowserStores();

  if (validateDeviceId(deviceId)) {
    try {
      const localId = await getOrCreateBrowserIdentity();
      const dev = await trustStore.getDevice(deviceId);
      const seq = ((dev && dev.revocationSeq) || 0) + 1;
      const rec = await signRevocation(localId, deviceId, seq, new Date());

      if (tombstoneStore) {
        await tombstoneStore.storeTombstone(rec);
      }

      if (purge) {
        await trustStore.unpairDevice(deviceId);
      } else {
        await trustStore.revokeDeviceWithRecord(rec);
      }
    } catch {
      if (purge) {
        await trustStore.unpairDevice(deviceId);
      } else {
        await trustStore.revokeDevice(deviceId);
      }
    }
  } else {
    if (purge) {
      await trustStore.unpairDevice(deviceId);
    } else {
      await trustStore.revokeDevice(deviceId);
    }
  }

  // Deletion of pair secrets is fatal/strict in both purge and non-purge paths (ADR 0010)
  if (secretStore) {
    await secretStore.deletePairSecret(deviceId);
  }
}

function createSignalPairingTransport(signal: {
  send(msg: SignalMsg): void;
  onMessage(handler: (msg: SignalMsg) => void): void;
  onClose(handler: (err: Error) => void): void;
}): PairingTransport {
  const queue: PairingMessage[] = [];
  let waitResolve: ((msg: PairingMessage) => void) | null = null;
  let waitReject: ((err: Error) => void) | null = null;

  signal.onMessage((msg: SignalMsg) => {
    if (
      msg &&
      typeof msg === 'object' &&
      (msg.type === MSG_PAIRING_REQUEST ||
        msg.type === MSG_PAIRING_RESPONSE ||
        msg.type === MSG_PAIRING_CONFIRM)
    ) {
      if (waitResolve) {
        const r = waitResolve;
        waitResolve = null;
        waitReject = null;
        r(msg as PairingMessage);
      } else {
        queue.push(msg as PairingMessage);
      }
    }
  });

  signal.onClose((err: Error) => {
    if (waitReject) {
      const r = waitReject;
      waitResolve = null;
      waitReject = null;
      r(err || new Error('signaling closed'));
    }
  });

  return {
    sendMessage: async (msg: PairingMessage) => {
      signal.send(msg);
    },
    receiveMessage: async () => {
      if (queue.length > 0) {
        return queue.shift()!;
      }
      return new Promise<PairingMessage>((resolve, reject) => {
        waitResolve = resolve;
        waitReject = reject;
      });
    },
  };
}

export async function pairTrustedDevice(
  server: string,
  code: string,
  name: string,
  autoAccept: boolean,
  dest: string,
): Promise<TrustedDeviceUI> {
  if (isDesktopApp() && window.go?.engine?.DeviceService) {
    return window.go.engine.DeviceService.PairDevice(server, code, name, autoAccept, dest);
  }

  if (!code || !code.trim()) {
    throw new Error('invite code is required');
  }

  const supported = await isPersistentTrustSupported();
  if (!supported && !browserTrustStore) {
    throw new Error(
      'Persistent device pairing requires WebCrypto and IndexedDB storage, which are unavailable in this context.',
    );
  }

  const { trustStore, secretStore, tombstoneStore } = getBrowserStores();
  const localId = await getOrCreateBrowserIdentity();
  const deviceName = name.trim() || 'Browser Device';

  const rendezvousCtrl = join({
    ...(server?.trim() ? { url: server.trim() } : {}),
    code: code.trim(),
  });

  let signal: ReturnType<typeof rendezvousCtrl.adoptSignaling> | null = null;
  try {
    const res = await rendezvousCtrl.done;
    signal = rendezvousCtrl.adoptSignaling();

    const transport = createSignalPairingTransport(signal);

    const cfg: PairingSessionConfig = {
      deviceName,
      capabilities: ['transfer.v1', 'transfer.v2', 'lan_direct'],
      masterKey: res.master,
      autoAccept,
      ...(autoAccept && dest?.trim() ? { destDir: dest.trim() } : {}),
    };

    const coordinator = new PairingCoordinator(
      trustStore,
      secretStore || undefined,
      tombstoneStore,
    );
    const pairResult = await coordinator.acceptPairing(transport, cfg, localId);

    let fp = '';
    try {
      fp = formatFingerprint(hexToBytes(pairResult.peerRecord.publicKey));
    } catch {
      fp = pairResult.peerRecord.deviceId.slice(0, 16);
    }

    return {
      deviceId: pairResult.peerRecord.deviceId,
      localLabel: pairResult.peerRecord.localLabel,
      fingerprint: fp,
      publicKey: pairResult.peerRecord.publicKey,
      status: 'online',
      revoked: false,
      lastSeenAt: pairResult.peerRecord.lastSeenAt,
      firstSeenAt: pairResult.peerRecord.firstSeenAt,
      capabilities: pairResult.peerRecord.capabilities,
      policy: pairResult.peerRecord.policy,
    };
  } finally {
    signal?.close();
  }
}

export interface PairingOfferController {
  readonly code: string | undefined;
  readonly done: Promise<TrustedDeviceUI>;
  cancel(reason?: string): void;
}

export function startPairingOffer(opts: {
  server?: string;
  name?: string;
  autoAccept?: boolean;
  dest?: string;
  onCode?: (code: string) => void;
}): PairingOfferController {
  const rendezvousCtrl = offer({
    ...(opts.server?.trim() ? { url: opts.server.trim() } : {}),
    ...(opts.onCode ? { onCode: opts.onCode } : {}),
  });

  const donePromise = (async (): Promise<TrustedDeviceUI> => {
    const supported = await isPersistentTrustSupported();
    if (!supported && !browserTrustStore) {
      rendezvousCtrl.cancel();
      throw new Error(
        'Persistent device pairing requires WebCrypto and IndexedDB storage, which are unavailable in this context.',
      );
    }

    const { trustStore, secretStore, tombstoneStore } = getBrowserStores();
    const localId = await getOrCreateBrowserIdentity();
    const deviceName = opts.name?.trim() || 'Browser Device';

    let signal: ReturnType<typeof rendezvousCtrl.adoptSignaling> | null = null;
    try {
      const res = await rendezvousCtrl.done;
      signal = rendezvousCtrl.adoptSignaling();

      const transport = createSignalPairingTransport(signal);

      const cfg: PairingSessionConfig = {
        deviceName,
        capabilities: ['transfer.v1', 'transfer.v2', 'lan_direct'],
        masterKey: res.master,
        autoAccept: !!opts.autoAccept,
        ...(opts.autoAccept && opts.dest?.trim() ? { destDir: opts.dest.trim() } : {}),
      };

      const coordinator = new PairingCoordinator(
        trustStore,
        secretStore || undefined,
        tombstoneStore,
      );
      const pairResult = await coordinator.initiatePairing(transport, cfg, localId);

      let fp = '';
      try {
        fp = formatFingerprint(hexToBytes(pairResult.peerRecord.publicKey));
      } catch {
        fp = pairResult.peerRecord.deviceId.slice(0, 16);
      }

      return {
        deviceId: pairResult.peerRecord.deviceId,
        localLabel: pairResult.peerRecord.localLabel,
        fingerprint: fp,
        publicKey: pairResult.peerRecord.publicKey,
        status: 'online',
        revoked: false,
        lastSeenAt: pairResult.peerRecord.lastSeenAt,
        firstSeenAt: pairResult.peerRecord.firstSeenAt,
        capabilities: pairResult.peerRecord.capabilities,
        policy: pairResult.peerRecord.policy,
      };
    } finally {
      signal?.close();
    }
  })();

  return {
    get code() {
      return rendezvousCtrl.code;
    },
    done: donePromise,
    cancel: (reason) => rendezvousCtrl.cancel(reason),
  };
}
