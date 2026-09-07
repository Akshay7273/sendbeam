/**
 * Pairing ceremony coordinator for TypeScript / Web (V19-PR08).
 * Drives the multi-step pairing ceremony on both initiator and responder sides,
 * enforcing mutual key confirmation, tombstone checks, and transactional persistence.
 *
 * Symmetrical counterpart to Go `packages/engine/trust/pairing_coordinator.go`.
 */

import { bytesToHex, constantTimeEqual, hexToBytes } from './bytes.js';
import { ERR_KEY_CONFLICT, ERR_LABEL_CONFLICT, ERR_TRUSTED_PEER_REVOKED } from './errors.js';
import type { DeviceIdentity } from './identity.js';
import {
  MSG_PAIRING_CONFIRM,
  MSG_PAIRING_REQUEST,
  MSG_PAIRING_RESPONSE,
  createPairingConfirm,
  createPairingRequest,
  createPairingResponse,
  derivePairCredential,
  verifyPairingConfirm,
  verifyPairingRequest,
  verifyPairingResponse,
  type PairingConfirm,
  type PairingMessage,
} from './pairing.js';
import type { TombstoneStore } from './tombstone-store.js';
import {
  RELATIONSHIP_CONTACT,
  type TrustPolicy,
  type TrustRecord,
  type TrustStore,
} from './trust-store.js';

export interface PairingSessionConfig {
  deviceName: string;
  capabilities: string[];
  masterKey: Uint8Array;
  autoAccept?: boolean;
  destDir?: string;
}

export interface PairingResult {
  peerRecord: TrustRecord;
  kPair: Uint8Array;
  credRef: string;
}

export interface SecretStore {
  setPairSecret(deviceId: string, secret: Uint8Array): Promise<void>;
  deletePairSecret(deviceId: string): Promise<void>;
}

export interface PairingTransport {
  sendMessage(msg: PairingMessage): Promise<void>;
  receiveMessage(): Promise<PairingMessage | string | Uint8Array>;
}

export function parsePairingMessage(raw: PairingMessage | string | Uint8Array): PairingMessage {
  if (typeof raw === 'string') {
    return JSON.parse(raw) as PairingMessage;
  }
  if (raw instanceof Uint8Array) {
    const text = new TextDecoder().decode(raw);
    return JSON.parse(text) as PairingMessage;
  }
  return raw;
}

export class PairingCoordinator {
  private readonly trustStore: TrustStore;
  private readonly secretStore?: SecretStore | undefined;
  private readonly tombstoneStore?: TombstoneStore | undefined;

  constructor(trustStore: TrustStore, secretStore?: SecretStore, tombstoneStore?: TombstoneStore) {
    this.trustStore = trustStore;
    this.secretStore = secretStore;
    this.tombstoneStore = tombstoneStore;
  }

  async initiatePairing(
    transport: PairingTransport,
    cfg: PairingSessionConfig,
    id: DeviceIdentity,
  ): Promise<PairingResult> {
    if (!transport) throw new Error('pairing transport required');
    if (!cfg.masterKey || cfg.masterKey.length === 0) throw new Error('master key required');
    if (!id) throw new Error('local identity required');

    // 1. Create and send PairingRequest
    const req = await createPairingRequest(id, cfg.deviceName, cfg.capabilities, cfg.masterKey);
    await transport.sendMessage(req);

    // 2. Receive and verify PairingResponse
    const rawResp = await transport.receiveMessage();
    const respMsg = parsePairingMessage(rawResp);
    if (!respMsg || respMsg.type !== MSG_PAIRING_RESPONSE) {
      throw new Error('expected pairing response message');
    }

    const reqNonce = hexToBytes(req.nonce);
    const { publicKey: peerPub, nonce: respNonce } = await verifyPairingResponse(
      respMsg,
      reqNonce,
      cfg.masterKey,
    );

    // 3. Derive pairwise credential
    const { kPair, credRef } = await derivePairCredential(
      cfg.masterKey,
      reqNonce,
      respNonce,
      id.publicKey,
      peerPub,
    );

    // 4. Verify no key or label conflict in trust store
    try {
      await this.checkConflict(respMsg.device_id, respMsg.device_name, peerPub);
    } catch (err) {
      await this.sendRejection(transport);
      throw err;
    }

    // 5. Send and receive PairingConfirm
    const confirm = await createPairingConfirm(kPair, respMsg.device_id, true);
    await transport.sendMessage(confirm);

    const rawPeerConf = await transport.receiveMessage();
    const peerConfMsg = parsePairingMessage(rawPeerConf);
    if (!peerConfMsg || peerConfMsg.type !== MSG_PAIRING_CONFIRM) {
      throw new Error('expected pairing confirm message');
    }
    await verifyPairingConfirm(peerConfMsg, kPair, id.deviceId);

    // 6. Record peer in local trust store & secret store (with rollback)
    const now = new Date().toISOString();
    const policy: TrustPolicy = {
      autoAccept: !!cfg.autoAccept,
      ...(cfg.autoAccept && cfg.destDir ? { autoAcceptDestDir: cfg.destDir } : {}),
      maxFileSizeBytes: 10 * 1024 * 1024 * 1024,
    };

    const record: TrustRecord = {
      deviceId: respMsg.device_id,
      publicKey: bytesToHex(peerPub),
      localLabel: respMsg.device_name,
      pairCredentialRef: credRef,
      relationship: RELATIONSHIP_CONTACT,
      capabilities: respMsg.capabilities || [],
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
      policy,
    };

    if (this.secretStore) {
      await this.secretStore.setPairSecret(record.deviceId, kPair);
    }

    try {
      await this.trustStore.addOrUpdateDevice(record);
    } catch (err) {
      if (this.secretStore) {
        try {
          await this.secretStore.deletePairSecret(record.deviceId);
        } catch {
          // ignore rollback failure
        }
      }
      throw new Error(`save trusted device: ${(err as Error).message}`);
    }

    return {
      peerRecord: record,
      kPair,
      credRef,
    };
  }

  async acceptPairing(
    transport: PairingTransport,
    cfg: PairingSessionConfig,
    id: DeviceIdentity,
  ): Promise<PairingResult> {
    if (!transport) throw new Error('pairing transport required');
    if (!cfg.masterKey || cfg.masterKey.length === 0) throw new Error('master key required');
    if (!id) throw new Error('local identity required');

    // 1. Receive and verify PairingRequest
    const rawReq = await transport.receiveMessage();
    const reqMsg = parsePairingMessage(rawReq);
    if (!reqMsg || reqMsg.type !== MSG_PAIRING_REQUEST) {
      throw new Error('expected pairing request message');
    }

    const { publicKey: peerPub, nonce: reqNonce } = await verifyPairingRequest(
      reqMsg,
      cfg.masterKey,
    );

    // 2. Check no key or label conflict in trust store
    try {
      await this.checkConflict(reqMsg.device_id, reqMsg.device_name, peerPub);
    } catch (err) {
      await this.sendRejection(transport);
      throw err;
    }

    // 3. Create and send PairingResponse
    const resp = await createPairingResponse(
      id,
      cfg.deviceName,
      cfg.capabilities,
      cfg.masterKey,
      reqNonce,
    );
    await transport.sendMessage(resp);

    // 4. Derive pairwise credential
    const respNonce = hexToBytes(resp.nonce);
    const { kPair, credRef } = await derivePairCredential(
      cfg.masterKey,
      reqNonce,
      respNonce,
      peerPub,
      id.publicKey,
    );

    // 5. Receive peer's PairingConfirm, then send ours
    const rawPeerConf = await transport.receiveMessage();
    const peerConfMsg = parsePairingMessage(rawPeerConf);
    if (!peerConfMsg || peerConfMsg.type !== MSG_PAIRING_CONFIRM) {
      throw new Error('expected pairing confirm message');
    }
    await verifyPairingConfirm(peerConfMsg, kPair, id.deviceId);

    const confirm = await createPairingConfirm(kPair, reqMsg.device_id, true);
    await transport.sendMessage(confirm);

    // 6. Record peer in local trust store & secret store (with rollback)
    const now = new Date().toISOString();
    const policy: TrustPolicy = {
      autoAccept: !!cfg.autoAccept,
      ...(cfg.autoAccept && cfg.destDir ? { autoAcceptDestDir: cfg.destDir } : {}),
      maxFileSizeBytes: 10 * 1024 * 1024 * 1024,
    };

    const record: TrustRecord = {
      deviceId: reqMsg.device_id,
      publicKey: bytesToHex(peerPub),
      localLabel: reqMsg.device_name,
      pairCredentialRef: credRef,
      relationship: RELATIONSHIP_CONTACT,
      capabilities: reqMsg.capabilities || [],
      firstSeenAt: now,
      lastSeenAt: now,
      revoked: false,
      policy,
    };

    if (this.secretStore) {
      await this.secretStore.setPairSecret(record.deviceId, kPair);
    }

    try {
      await this.trustStore.addOrUpdateDevice(record);
    } catch (err) {
      if (this.secretStore) {
        try {
          await this.secretStore.deletePairSecret(record.deviceId);
        } catch {
          // ignore rollback failure
        }
      }
      throw new Error(`save trusted device: ${(err as Error).message}`);
    }

    return {
      peerRecord: record,
      kPair,
      credRef,
    };
  }

  private async checkConflict(
    deviceId: string,
    deviceName: string,
    pubKey: Uint8Array,
  ): Promise<void> {
    // ADR 0010 §4.5: If the peer has an active tombstone record, reject pairing fail-closed
    if (this.tombstoneStore && (await this.tombstoneStore.hasTombstone(deviceId))) {
      throw new Error(ERR_TRUSTED_PEER_REVOKED);
    }

    const existing = await this.trustStore.getDevice(deviceId);
    if (existing) {
      if (existing.revoked) {
        throw new Error(ERR_TRUSTED_PEER_REVOKED);
      }
      const existingPub = hexToBytes(existing.publicKey);
      if (!constantTimeEqual(existingPub, pubKey)) {
        throw new Error(ERR_KEY_CONFLICT);
      }
    }

    // Check for active trusted devices with the same label but different device ID
    const list = await this.trustStore.listDevices();
    for (const rec of list) {
      if (
        rec.deviceId !== deviceId &&
        rec.localLabel.trim().toLowerCase() === deviceName.trim().toLowerCase() &&
        !rec.revoked
      ) {
        throw new Error(ERR_LABEL_CONFLICT);
      }
    }
  }

  private async sendRejection(transport: PairingTransport): Promise<void> {
    const rej: PairingConfirm = {
      type: MSG_PAIRING_CONFIRM,
      status: 'rejected',
    };
    try {
      await transport.sendMessage(rej);
    } catch {
      // ignore errors when sending rejection frame
    }
  }
}
