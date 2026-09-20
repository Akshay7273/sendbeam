import type { TrustPolicy } from '@sendbeam/protocol';

export type DevicePresenceStatus = 'lan_direct' | 'online' | 'offline' | 'revoked';

export interface TrustedDeviceUI {
  deviceId: string;
  localLabel: string;
  fingerprint: string;
  publicKey: string;
  status: DevicePresenceStatus;
  revoked: boolean;
  revokedBy?: string | undefined;
  revocationSeq?: number | undefined;
  lastSeenAt: string;
  firstSeenAt: string;
  capabilities: string[];
  policy: TrustPolicy;
  directEndpoint?: string | undefined;
}

export interface IncomingTransferRequest {
  transferId: string;
  senderDeviceId: string;
  senderLabel: string;
  senderFingerprint: string;
  fileCount: number;
  totalBytes: number;
  files: Array<{ name: string; size: number }>;
  /**
   * V20-PR06: present for encrypted text/link handoff envelopes. The consent UI
   * renders these inertly with deliberate Copy/Save/Open instead of a download.
   */
  contentKind?: 'text' | 'link';
}

export type BroadcastDeviceStatus =
  'pending' | 'connecting' | 'sending' | 'ok' | 'offline' | 'refused' | 'failed';

export interface BroadcastDeviceState {
  deviceId: string;
  label: string;
  status: BroadcastDeviceStatus;
  progressBytes: number;
  totalBytes: number;
  durationMs?: number;
  digest?: string;
  error?: string;
}
