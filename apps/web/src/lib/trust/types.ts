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
}
