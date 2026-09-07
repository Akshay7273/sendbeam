import type { TrustPolicy } from '@sendbeam/protocol';

export const WAILS_SERVICES = {
  Service: 'github.com/sendbeam/desktop/internal/engine.Service',
  Transfer: 'github.com/sendbeam/desktop/internal/engine.TransferService',
  Update: 'github.com/sendbeam/desktop/internal/engine.UpdateService',
  Device: 'github.com/sendbeam/desktop/internal/engine.DeviceService',
} as const;

export const WAILS_EVENTS = {
  Transfer: 'sendbeam:transfer',
  Consent: 'sendbeam:consent',
  Devices: 'sendbeam:devices',
  Update: 'sendbeam:update',
  PairingComplete: 'sendbeam:pairing_complete',
  PairingFailed: 'sendbeam:pairing_failed',
} as const;

export interface TrustedDeviceView {
  deviceId: string;
  localLabel: string;
  fingerprint: string;
  publicKey: string;
  status: 'lan_direct' | 'online' | 'offline' | 'revoked';
  revoked: boolean;
  lastSeenAt: string;
  firstSeenAt: string;
  capabilities: string[];
  policy: TrustPolicy;
  directEndpoint?: string;
}

export interface PairingOfferResult {
  code: string;
  qr: string;
}

export interface TransferHandle {
  id: string;
  role: 'send' | 'receive';
}

export interface TargetResult {
  target_id: string;
  label: string;
  status: 'ok' | 'offline' | 'refused' | 'failed';
  digest?: string;
  size?: number;
  duration_ms: number;
  error?: string;
  outcome?: {
    name: string;
    size: number;
    digest: string;
    path?: string;
  };
}

export interface ConsentRequest {
  transferId: string;
  peerDeviceId: string;
  peerName?: string;
  fingerprint: string;
  fileName: string;
  fileCount: number;
  totalSize: number;
  destDir?: string;
}

export interface ConsentDecision {
  accepted: boolean;
  destDir?: string;
  reason?: string;
}

export interface DurableTransferItem {
  transferId: string;
  role: 'send' | 'receive';
  totalBytes: number;
  committedBytes: number;
  files: number;
  createdAt: number;
  updatedAt: number;
  status: string;
  resumable: boolean;
  paths?: string[];
}

export interface DurableInspectResult {
  transferId: string;
  totalBytes: number;
  committedBytes: number;
  createdAt: number;
  updatedAt: number;
  protocolVersion: string;
  manifestFingerprint: string;
  journalPath: string;
  partialDir: string;
  resumable: boolean;
  problems?: string[];
  files?: { name: string; size: number }[];
}

export interface DesktopConfig {
  downloadDir?: string;
  serverUrl?: string;
  closeToTray?: boolean;
  startMinimized?: boolean;
  updateChannel?: string;
  iceServers?: string[];
}

export interface EngineInfo {
  version: string;
  platform: string;
  buildTime: string;
}

export interface EngineCaps {
  features: string[];
  protocolVersion: string;
}

export interface SelfCheckResult {
  ok: boolean;
  problems?: string[];
}

export interface UpdateStatus {
  state: string;
  currentVersion: string;
  latestVersion?: string;
  releaseNotes?: string;
  channel: string;
  error?: string;
}

export type WailsCaller = (name: string, ...args: unknown[]) => Promise<unknown>;
export type WailsEventSubscriber = (name: string, callback: (data: unknown) => void) => () => void;

export interface DeviceServiceAdapter {
  listTrustedDevices(): Promise<TrustedDeviceView[]>;
  pairDevice(
    server: string,
    code: string,
    label: string,
    autoAccept: boolean,
    destDir: string,
  ): Promise<TrustedDeviceView>;
  startPairingOffer(
    server: string,
    label: string,
    autoAccept: boolean,
    destDir: string,
  ): Promise<PairingOfferResult>;
  cancelPairingOffer(): Promise<void>;
  renameDevice(deviceId: string, newLabel: string): Promise<void>;
  updateDevicePolicy(deviceId: string, policy: TrustPolicy): Promise<void>;
  unpairDevice(deviceId: string, purge: boolean): Promise<void>;
}

export interface TransferServiceAdapter {
  send(paths: string[], server?: string): Promise<TransferHandle>;
  sendToDevice(paths: string[], deviceId: string, server?: string): Promise<TransferHandle>;
  broadcastSend(paths: string[], deviceIds: string[], server?: string): Promise<TargetResult[]>;
  receive(code: string, destDir?: string, server?: string): Promise<TransferHandle>;
  pause(id: string): Promise<void>;
  resume(id: string): Promise<void>;
  cancel(id: string): Promise<void>;
  respondConsent(transferId: string, decision: ConsentDecision): Promise<void>;
  pendingConsents(): Promise<ConsentRequest[]>;
  pickFiles(): Promise<{ paths: string[]; error?: string }>;
  pickDestination(): Promise<{ path: string; error?: string }>;
  listInterrupted(outDir?: string): Promise<DurableTransferItem[]>;
  inspectInterrupted(transferId: string, outDir?: string): Promise<DurableInspectResult>;
  resumeInterrupted(
    transferId: string,
    code: string,
    destDir?: string,
    server?: string,
  ): Promise<TransferHandle>;
  discardInterrupted(transferId: string, outDir?: string): Promise<void>;
  discardAllInterrupted(outDir?: string): Promise<void>;
  revealCompleted(id: string): Promise<void>;
  getConfig(): Promise<DesktopConfig>;
  saveConfig(cfg: DesktopConfig): Promise<void>;
}

export interface UpdateServiceAdapter {
  checkUpdate(channel: string): Promise<UpdateStatus>;
  setChannel(channel: string): Promise<void>;
  applyUpdate(): Promise<UpdateStatus>;
  getStatus(): Promise<UpdateStatus>;
}

export interface EngineServiceAdapter {
  info(): Promise<EngineInfo>;
  caps(): Promise<EngineCaps>;
  selfCheck(): Promise<SelfCheckResult>;
}

export interface WailsBridge {
  device: DeviceServiceAdapter;
  transfer: TransferServiceAdapter;
  update: UpdateServiceAdapter;
  engine: EngineServiceAdapter;
  events: {
    on(name: string, cb: (data: unknown) => void): () => void;
  };
}

export function createDeviceServiceAdapter(call: WailsCaller): DeviceServiceAdapter {
  return {
    listTrustedDevices: () =>
      call(`${WAILS_SERVICES.Device}.ListTrustedDevices`) as Promise<TrustedDeviceView[]>,
    pairDevice: (server, code, label, autoAccept, destDir) =>
      call(
        `${WAILS_SERVICES.Device}.PairDevice`,
        server,
        code,
        label,
        autoAccept,
        destDir,
      ) as Promise<TrustedDeviceView>,
    startPairingOffer: (server, label, autoAccept, destDir) =>
      call(
        `${WAILS_SERVICES.Device}.StartPairingOffer`,
        server,
        label,
        autoAccept,
        destDir,
      ) as Promise<PairingOfferResult>,
    cancelPairingOffer: () => call(`${WAILS_SERVICES.Device}.CancelPairingOffer`) as Promise<void>,
    renameDevice: (deviceId, newLabel) =>
      call(`${WAILS_SERVICES.Device}.RenameDevice`, deviceId, newLabel) as Promise<void>,
    updateDevicePolicy: (deviceId, policy) =>
      call(`${WAILS_SERVICES.Device}.UpdateDevicePolicy`, deviceId, policy) as Promise<void>,
    unpairDevice: (deviceId, purge) =>
      call(`${WAILS_SERVICES.Device}.UnpairDevice`, deviceId, purge) as Promise<void>,
  };
}

export function createTransferServiceAdapter(call: WailsCaller): TransferServiceAdapter {
  return {
    send: (paths, server = '') =>
      call(`${WAILS_SERVICES.Transfer}.Send`, paths, server) as Promise<TransferHandle>,
    sendToDevice: (paths, deviceId, server = '') =>
      call(
        `${WAILS_SERVICES.Transfer}.SendToDevice`,
        paths,
        deviceId,
        server,
      ) as Promise<TransferHandle>,
    broadcastSend: (paths, deviceIds, server = '') =>
      call(`${WAILS_SERVICES.Transfer}.BroadcastSend`, paths, deviceIds, server) as Promise<
        TargetResult[]
      >,
    receive: (code, destDir = '', server = '') =>
      call(`${WAILS_SERVICES.Transfer}.Receive`, code, destDir, server) as Promise<TransferHandle>,
    pause: (id) => call(`${WAILS_SERVICES.Transfer}.Pause`, id) as Promise<void>,
    resume: (id) => call(`${WAILS_SERVICES.Transfer}.Resume`, id) as Promise<void>,
    cancel: (id) => call(`${WAILS_SERVICES.Transfer}.Cancel`, id) as Promise<void>,
    respondConsent: (transferId, decision) =>
      call(`${WAILS_SERVICES.Transfer}.RespondConsent`, transferId, decision) as Promise<void>,
    pendingConsents: () =>
      call(`${WAILS_SERVICES.Transfer}.PendingConsents`) as Promise<ConsentRequest[]>,
    pickFiles: () =>
      call(`${WAILS_SERVICES.Transfer}.PickFiles`) as Promise<{
        paths: string[];
        error?: string;
      }>,
    pickDestination: () =>
      call(`${WAILS_SERVICES.Transfer}.PickDestination`) as Promise<{
        path: string;
        error?: string;
      }>,
    listInterrupted: (outDir = '') =>
      call(`${WAILS_SERVICES.Transfer}.ListInterrupted`, outDir) as Promise<DurableTransferItem[]>,
    inspectInterrupted: (transferId, outDir = '') =>
      call(
        `${WAILS_SERVICES.Transfer}.InspectInterrupted`,
        transferId,
        outDir,
      ) as Promise<DurableInspectResult>,
    resumeInterrupted: (transferId, code, destDir = '', server = '') =>
      call(
        `${WAILS_SERVICES.Transfer}.ResumeInterrupted`,
        transferId,
        code,
        destDir,
        server,
      ) as Promise<TransferHandle>,
    discardInterrupted: (transferId, outDir = '') =>
      call(`${WAILS_SERVICES.Transfer}.DiscardInterrupted`, transferId, outDir) as Promise<void>,
    discardAllInterrupted: (outDir = '') =>
      call(`${WAILS_SERVICES.Transfer}.DiscardAllInterrupted`, outDir) as Promise<void>,
    revealCompleted: (id) =>
      call(`${WAILS_SERVICES.Transfer}.RevealCompleted`, id) as Promise<void>,
    getConfig: () => call(`${WAILS_SERVICES.Transfer}.GetConfig`) as Promise<DesktopConfig>,
    saveConfig: (cfg) => call(`${WAILS_SERVICES.Transfer}.SaveConfig`, cfg) as Promise<void>,
  };
}

export function createUpdateServiceAdapter(call: WailsCaller): UpdateServiceAdapter {
  return {
    checkUpdate: (channel) =>
      call(`${WAILS_SERVICES.Update}.CheckUpdate`, channel) as Promise<UpdateStatus>,
    setChannel: (channel) => call(`${WAILS_SERVICES.Update}.SetChannel`, channel) as Promise<void>,
    applyUpdate: () => call(`${WAILS_SERVICES.Update}.ApplyUpdate`) as Promise<UpdateStatus>,
    getStatus: () => call(`${WAILS_SERVICES.Update}.GetStatus`) as Promise<UpdateStatus>,
  };
}

export function createEngineServiceAdapter(call: WailsCaller): EngineServiceAdapter {
  return {
    info: () => call(`${WAILS_SERVICES.Service}.Info`) as Promise<EngineInfo>,
    caps: () => call(`${WAILS_SERVICES.Service}.Caps`) as Promise<EngineCaps>,
    selfCheck: () => call(`${WAILS_SERVICES.Service}.SelfCheck`) as Promise<SelfCheckResult>,
  };
}

export function isWailsV3Available(): boolean {
  return (
    typeof window !== 'undefined' &&
    !!(window as unknown as { wails?: { Call?: { ByName?: unknown } } }).wails?.Call?.ByName
  );
}

export function getWailsBridge(): WailsBridge | null {
  if (!isWailsV3Available()) {
    return null;
  }
  const w = window as unknown as {
    wails: {
      Call: { ByName(name: string, ...args: unknown[]): Promise<unknown> };
      Events?: { On(name: string, callback: (data: unknown) => void): () => void };
    };
  };
  const caller: WailsCaller = (name, ...args) => w.wails.Call.ByName(name, ...args);
  const subscriber: WailsEventSubscriber = (name, cb) => {
    if (w.wails.Events?.On) {
      return w.wails.Events.On(name, cb);
    }
    return () => {};
  };

  return {
    device: createDeviceServiceAdapter(caller),
    transfer: createTransferServiceAdapter(caller),
    update: createUpdateServiceAdapter(caller),
    engine: createEngineServiceAdapter(caller),
    events: { on: subscriber },
  };
}
