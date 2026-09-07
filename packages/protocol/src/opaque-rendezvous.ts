/**
 * Ephemeral opaque rendezvous state machine (V19-PR05).
 * Connects time-windowed opaque handles to authenticated forward-secret sessions (sendbeam/3).
 */

import type { Role } from './signaling.js';
import { validateRendezvousHandle } from './presence.js';
import type { DeviceIdentity } from './identity.js';
import {
  DOMAIN_TRUSTED_CONFIRM_INIT_3,
  DOMAIN_TRUSTED_CONFIRM_RESP_3,
  createTrustedAuthConfirm,
  createTrustedAuthInitV3,
  createTrustedAuthResponseV3,
  deriveTrustedSessionKeysV3,
  verifyTrustedAuthConfirm,
  verifyTrustedAuthInitV3,
  verifyTrustedAuthResponseV3,
  type TrustedAuthConfirm,
  type TrustedAuthInit,
  type TrustedAuthResponse,
} from './trusted-auth.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from './bytes.js';
import { randomBytes } from './webcrypto.js';

export type OpaqueRendezvousPhase =
  | 'idle'
  | 'rendezvous_sent'
  | 'waiting_peer'
  | 'paired'
  | 'authenticating'
  | 'established'
  | 'failed';

export interface OpaqueRendezvousResult {
  readonly role: Role;
  readonly handle: string;
  readonly master: Uint8Array;
  readonly sendKey: Uint8Array;
  readonly recvKey: Uint8Array;
  readonly negotiatedCaps: string[];
  readonly peerDeviceId: string;
}

export interface OpaqueRendezvousOptions {
  readonly role: Role;
  readonly handle: string;
  readonly localIdentity: DeviceIdentity;
  readonly peerDeviceId: string;
  readonly peerPublicKey: string | Uint8Array;
  readonly kPair: Uint8Array;
  readonly pairCredentialRef: string;
  readonly localCapabilities?: string[] | undefined;
  readonly send: (msg: unknown) => Promise<void> | void;
  readonly onPhase?: ((phase: OpaqueRendezvousPhase) => void) | undefined;
  readonly timeoutMs?: number | undefined;
}

function getPeerPubKeyBytes(peerPublicKey: string | Uint8Array): Uint8Array {
  return typeof peerPublicKey === 'string' ? hexToBytes(peerPublicKey) : peerPublicKey;
}

export class OpaqueRendezvousSession {
  private phase: OpaqueRendezvousPhase = 'idle';
  private readonly options: OpaqueRendezvousOptions;
  private privScalar?: Uint8Array | undefined;
  private pubHex?: string | undefined;
  private nonceHex?: string | undefined;
  private initMsg?: TrustedAuthInit | undefined;
  private sessionMaster?: Uint8Array | undefined;
  private sendKey?: Uint8Array | undefined;
  private recvKey?: Uint8Array | undefined;
  private negotiatedCaps?: string[] | undefined;
  private peerConfirmed = false;
  private selfConfirmed = false;

  private resolvePromise?: ((result: OpaqueRendezvousResult) => void) | undefined;
  private rejectPromise?: ((err: Error) => void) | undefined;
  readonly result: Promise<OpaqueRendezvousResult>;

  constructor(options: OpaqueRendezvousOptions) {
    this.options = options;
    this.result = new Promise<OpaqueRendezvousResult>((resolve, reject) => {
      this.resolvePromise = resolve;
      this.rejectPromise = reject;
    });
  }

  getPhase(): OpaqueRendezvousPhase {
    return this.phase;
  }

  private setPhase(newPhase: OpaqueRendezvousPhase): void {
    this.phase = newPhase;
    this.options.onPhase?.(newPhase);
  }

  async start(): Promise<void> {
    if (this.phase !== 'idle') {
      return;
    }
    if (!validateRendezvousHandle(this.options.handle)) {
      this.fail(new Error('invalid_handle'));
      return;
    }

    this.setPhase('rendezvous_sent');
    await this.options.send({
      type: 'rendezvous',
      handle: this.options.handle,
      role: this.options.role,
    });
  }

  async resume(): Promise<void> {
    if (!validateRendezvousHandle(this.options.handle)) {
      this.fail(new Error('invalid_handle'));
      return;
    }
    await this.options.send({
      type: 'resume',
      handle: this.options.handle,
      role: this.options.role,
    });
  }

  async handleMessage(msg: unknown): Promise<void> {
    if (this.phase === 'failed' || this.phase === 'established') {
      return;
    }

    const m = msg as Record<string, unknown>;
    try {
      switch (m['type']) {
        case 'created':
          if (this.phase === 'rendezvous_sent') {
            this.setPhase('waiting_peer');
          }
          break;

        case 'peer-joined':
          this.setPhase('paired');
          await this.onPaired();
          break;

        case 'resumed':
          // Re-attached to lingering room; proceed with auth if paired
          break;

        case 'peer_rejoined':
          // Partner re-attached; re-run auth
          this.setPhase('paired');
          await this.onPaired();
          break;

        case 'peer_left':
          this.fail(new Error('peer_left'));
          break;

        case 'error':
          this.fail(new Error(typeof m['code'] === 'string' ? m['code'] : 'signaling_error'));
          break;

        case 'trusted_auth_init':
          await this.onTrustedAuthInit(msg as TrustedAuthInit);
          break;

        case 'trusted_auth_response':
          await this.onTrustedAuthResponse(msg as TrustedAuthResponse);
          break;

        case 'trusted_auth_confirm':
          await this.onTrustedAuthConfirm(msg as TrustedAuthConfirm);
          break;

        default:
          break;
      }
    } catch (err: unknown) {
      this.fail(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private async onPaired(): Promise<void> {
    this.setPhase('authenticating');
    if (this.options.role === 'offerer') {
      // Offerer acts as initiator
      const priv = x25519.utils.randomSecretKey();
      this.privScalar = priv;
      const pub = x25519.getPublicKey(priv);
      this.pubHex = bytesToHex(pub);
      const nonce = randomBytes(32);
      this.nonceHex = bytesToHex(nonce);

      const init = await createTrustedAuthInitV3(
        this.options.localIdentity,
        this.options.peerDeviceId,
        this.options.pairCredentialRef,
        this.options.kPair,
        this.options.localCapabilities ?? ['transfer.v1', 'padding'],
        pub,
        nonce,
      );
      this.initMsg = init;
      await this.options.send(init);
    }
  }

  private async onTrustedAuthInit(init: TrustedAuthInit): Promise<void> {
    if (this.options.role !== 'joiner') {
      return;
    }
    this.initMsg = init;

    // Verify init message
    const peerPubBytes = getPeerPubKeyBytes(this.options.peerPublicKey);
    const { ephemeralPub: peerEphemPub, nonce: peerNonce } = await verifyTrustedAuthInitV3(
      init,
      this.options.kPair,
      peerPubBytes,
      this.options.localIdentity.deviceId,
    );

    // Generate responder ephemeral keypair
    const privB = x25519.utils.randomSecretKey();
    const pubB = x25519.getPublicKey(privB);
    const nonceB = randomBytes(32);

    const localCaps = this.options.localCapabilities ?? ['transfer.v1', 'padding'];

    const response = await createTrustedAuthResponseV3(
      this.options.localIdentity,
      init,
      this.options.kPair,
      localCaps,
      pubB,
      nonceB,
    );
    await this.options.send(response);

    // Derive session keys
    const ss = x25519.getSharedSecret(privB, peerEphemPub);
    // Zeroize privB
    privB.fill(0);

    const keys = await deriveTrustedSessionKeysV3(
      this.options.kPair,
      ss,
      peerEphemPub,
      pubB,
      peerNonce,
      nonceB,
      init.initiator_device_id,
      this.options.localIdentity.deviceId,
      init.capabilities,
      localCaps,
    );

    this.sessionMaster = keys.sessionMaster;
    // For joiner (responder): sendKey is r2i, recvKey is i2r
    this.sendKey = keys.responderToInitiatorKey;
    this.recvKey = keys.initiatorToResponderKey;
    this.negotiatedCaps = keys.negotiatedCapabilities;

    // Send confirmation
    const confirm = await createTrustedAuthConfirm(
      this.sessionMaster,
      DOMAIN_TRUSTED_CONFIRM_RESP_3,
      this.options.localIdentity.deviceId,
      true,
    );
    this.selfConfirmed = true;
    await this.options.send(confirm);
    this.checkEstablished();
  }

  private async onTrustedAuthResponse(resp: TrustedAuthResponse): Promise<void> {
    if (this.options.role !== 'offerer' || !this.initMsg || !this.privScalar) {
      return;
    }
    if (resp.status !== 'accepted' || !resp.ephemeral_pub || !resp.nonce) {
      throw new Error(`peer_rejected_auth: ${resp.status}`);
    }

    const peerPubBytes = getPeerPubKeyBytes(this.options.peerPublicKey);
    const { ephemeralPub: peerEphemPub, nonce: peerNonce } = await verifyTrustedAuthResponseV3(
      resp,
      this.initMsg,
      this.options.kPair,
      peerPubBytes,
      this.options.localIdentity.deviceId,
    );

    const ss = x25519.getSharedSecret(this.privScalar, peerEphemPub);
    // Zeroize privScalar
    this.privScalar.fill(0);
    this.privScalar = undefined;

    const myEphemPub = hexToBytes(this.pubHex!);
    const myNonce = hexToBytes(this.nonceHex!);

    const keys = await deriveTrustedSessionKeysV3(
      this.options.kPair,
      ss,
      myEphemPub,
      peerEphemPub,
      myNonce,
      peerNonce,
      this.options.localIdentity.deviceId,
      this.options.peerDeviceId,
      this.initMsg.capabilities,
      resp.capabilities ?? [],
    );

    this.sessionMaster = keys.sessionMaster;
    // For offerer (initiator): sendKey is i2r, recvKey is r2i
    this.sendKey = keys.initiatorToResponderKey;
    this.recvKey = keys.responderToInitiatorKey;
    this.negotiatedCaps = keys.negotiatedCapabilities;

    // Send confirmation
    const confirm = await createTrustedAuthConfirm(
      this.sessionMaster,
      DOMAIN_TRUSTED_CONFIRM_INIT_3,
      this.options.localIdentity.deviceId,
      true,
    );
    this.selfConfirmed = true;
    await this.options.send(confirm);
    this.checkEstablished();
  }

  private async onTrustedAuthConfirm(confirm: TrustedAuthConfirm): Promise<void> {
    if (!this.sessionMaster) {
      throw new Error('session_master_missing');
    }

    const domain =
      this.options.role === 'offerer'
        ? DOMAIN_TRUSTED_CONFIRM_RESP_3
        : DOMAIN_TRUSTED_CONFIRM_INIT_3;
    await verifyTrustedAuthConfirm(confirm, this.sessionMaster, domain, this.options.peerDeviceId);

    this.peerConfirmed = true;
    this.checkEstablished();
  }

  private checkEstablished(): void {
    if (
      this.selfConfirmed &&
      this.peerConfirmed &&
      this.sessionMaster &&
      this.sendKey &&
      this.recvKey
    ) {
      this.setPhase('established');
      this.resolvePromise?.({
        role: this.options.role,
        handle: this.options.handle,
        master: this.sessionMaster,
        sendKey: this.sendKey,
        recvKey: this.recvKey,
        negotiatedCaps: this.negotiatedCaps ?? [],
        peerDeviceId: this.options.peerDeviceId,
      });
    }
  }

  private fail(err: Error): void {
    if (this.privScalar) {
      this.privScalar.fill(0);
      this.privScalar = undefined;
    }
    this.setPhase('failed');
    this.rejectPromise?.(err);
  }
}
