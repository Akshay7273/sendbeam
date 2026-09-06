/**
 * Trusted-session authentication messages, pairwise authenticated session key derivation,
 * and mutual challenge verification for paired SendBeam devices (V15-PR03).
 *
 * Matches Go `packages/wire/trusted_auth.go` byte-for-byte.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, concatBytes, hexToBytes, utf8 } from './bytes.js';
import {
  deriveDeviceId,
  signDeviceMessage,
  validateDeviceId,
  verifyDeviceSignature,
  type DeviceIdentity,
} from './identity.js';
import type { RevocationRecord } from './revocation.js';
import { hkdfSha256, hmacSha256, randomBytes, sha256 } from './webcrypto.js';

export const MSG_TRUSTED_AUTH_INIT = 'trusted_auth_init';
export const MSG_TRUSTED_AUTH_RESPONSE = 'trusted_auth_response';
export const MSG_TRUSTED_AUTH_CONFIRM = 'trusted_auth_confirm';

export const TRUSTED_AUTH_PROTOCOL_VERSION = 'sendbeam/2';
export const TRUSTED_AUTH_PROTOCOL_VERSION_V3 = 'sendbeam/3';

export const DOMAIN_TRUSTED_INIT = 'sendbeam/2 trusted-init:';
export const DOMAIN_TRUSTED_INIT_MAC = 'sendbeam/2 trusted-init-mac:';
export const DOMAIN_TRUSTED_RESP = 'sendbeam/2 trusted-resp:';
export const DOMAIN_TRUSTED_RESP_MAC = 'sendbeam/2 trusted-resp-mac:';
export const DOMAIN_TRUSTED_MASTER = 'sendbeam/2 session-master:';
export const DOMAIN_TRUSTED_INIT_TO_RESP_KEY = 'sendbeam/2 initiator-to-responder key';
export const DOMAIN_TRUSTED_RESP_TO_INIT_KEY = 'sendbeam/2 responder-to-initiator key';
export const DOMAIN_TRUSTED_CONFIRM_INIT = 'sendbeam/2 confirm-init:';
export const DOMAIN_TRUSTED_CONFIRM_RESP = 'sendbeam/2 confirm-resp:';

// sendbeam/3 domain constants (ADR 0010)
export const DOMAIN_TRUSTED_INIT_3 = 'sendbeam/3 trusted-init:';
export const DOMAIN_TRUSTED_INIT_MAC_3 = 'sendbeam/3 trusted-init-mac:';
export const DOMAIN_TRUSTED_RESP_3 = 'sendbeam/3 trusted-resp:';
export const DOMAIN_TRUSTED_RESP_MAC_3 = 'sendbeam/3 trusted-resp-mac:';
export const DOMAIN_TRUSTED_MASTER_3 = 'sendbeam/3 session-master:';
export const DOMAIN_TRUSTED_INIT_TO_RESP_3 = 'sendbeam/3 initiator-to-responder key';
export const DOMAIN_TRUSTED_RESP_TO_INIT_3 = 'sendbeam/3 responder-to-initiator key';
export const DOMAIN_TRUSTED_CONFIRM_INIT_3 = 'sendbeam/3 confirm-init:';
export const DOMAIN_TRUSTED_CONFIRM_RESP_3 = 'sendbeam/3 confirm-resp:';
export const DOMAIN_TRUSTED_TRANSCRIPT_3 = 'sendbeam/3 transcript:';

export const TRUSTED_AUTH_NONCE_SIZE = 32;
export const TRUSTED_AUTH_EPHEMERAL_SIZE = 32;
export const X25519_KEY_SIZE = 32;
export const MAX_TRUSTED_TIMESTAMP_SKEW_MS = 5 * 60 * 1000; // 5 minutes

export interface TrustedAuthInit {
  readonly type: typeof MSG_TRUSTED_AUTH_INIT;
  readonly protocol_version: string;
  readonly initiator_device_id: string;
  readonly responder_device_id: string;
  readonly pair_credential_ref: string;
  readonly ephemeral_pub: string;
  readonly nonce: string;
  readonly capabilities: string[];
  readonly timestamp: string;
  readonly signature: string;
  readonly auth_tag: string;
  readonly revocations?: RevocationRecord[];
}

export interface TrustedAuthResponse {
  readonly type: typeof MSG_TRUSTED_AUTH_RESPONSE;
  readonly protocol_version: string;
  readonly status: 'accepted' | 'rejected' | 'revoked';
  readonly responder_device_id: string;
  readonly ephemeral_pub?: string;
  readonly nonce?: string;
  readonly capabilities?: string[];
  readonly signature?: string;
  readonly auth_tag?: string;
  readonly revocations?: RevocationRecord[];
}

export interface TrustedAuthConfirm {
  readonly type: typeof MSG_TRUSTED_AUTH_CONFIRM;
  readonly status: 'ready' | 'rejected';
  readonly auth_tag?: string;
}

export type TrustedAuthMessage = TrustedAuthInit | TrustedAuthResponse | TrustedAuthConfirm;

export interface TrustedSessionKeys {
  readonly sessionMaster: Uint8Array;
  readonly initiatorToResponderKey: Uint8Array;
  readonly responderToInitiatorKey: Uint8Array;
  readonly negotiatedCapabilities: string[];
}

/**
 * Constant-time hex string comparison.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Deterministic canonical SHA-256 digest of capability strings.
 */
export async function hashCapabilities(caps: readonly string[]): Promise<Uint8Array> {
  const sorted = [...caps].sort();
  const joined = sorted.join(',');
  return sha256(utf8(joined));
}

/**
 * Intersect two capability lists and sort alphabetically.
 */
export function intersectCapabilities(a: readonly string[], b: readonly string[]): string[] {
  const set = new Set(a);
  const result = b.filter((item) => set.has(item));
  result.sort();
  return result;
}

/**
 * Build the binary payload signed by the initiator in TrustedAuthInit.
 */
export async function buildTrustedInitChallenge(
  kPairHash: Uint8Array,
  ephemPub: Uint8Array,
  nonce: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
  timestamp: string,
): Promise<Uint8Array> {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_INIT),
    kPairHash,
    ephemPub,
    nonce,
    utf8(initId),
    utf8(respId),
    capsHash,
    utf8(timestamp),
  );
}

/**
 * Build the binary payload signed by the responder in TrustedAuthResponse.
 */
export async function buildTrustedRespChallenge(
  kPairHash: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
): Promise<Uint8Array> {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_RESP),
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    utf8(initId),
    utf8(respId),
    capsHash,
  );
}

/**
 * Build the binary payload signed by the initiator in sendbeam/3 (ADR 0010).
 */
export function buildTrustedInitChallengeV3(
  kPairHash: Uint8Array,
  ephemPub: Uint8Array,
  nonce: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
  timestamp: string,
): Uint8Array {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_INIT_3),
    kPairHash,
    ephemPub,
    nonce,
    utf8(initId),
    utf8(respId),
    capsHash,
    utf8(timestamp),
  );
}

/**
 * Build the binary payload signed by the responder in sendbeam/3 (ADR 0010).
 */
export function buildTrustedRespChallengeV3(
  kPairHash: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
): Uint8Array {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_RESP_3),
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    utf8(initId),
    utf8(respId),
    capsHash,
  );
}

/**
 * Build the canonical transcript bound into the sendbeam/3 session master key (ADR 0010).
 */
export function buildTrustedTranscriptV3(
  kPairHash: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsHash: Uint8Array,
): Uint8Array {
  return concatBytes(
    utf8(DOMAIN_TRUSTED_TRANSCRIPT_3),
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    utf8(initId),
    utf8(respId),
    capsHash,
  );
}

export interface X25519KeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

/**
 * Generate a fresh ephemeral X25519 keypair.
 */
export function generateX25519KeyPair(): X25519KeyPair {
  const kp = x25519.keygen();
  return {
    secretKey: kp.secretKey,
    publicKey: kp.publicKey,
  };
}

/**
 * Compute the Diffie-Hellman shared secret between private scalar and peer public key.
 * Validates 32-byte key size and rejects low-order / all-zero points.
 */
export function computeX25519SharedSecret(
  secretKey: Uint8Array,
  peerPubKey: Uint8Array,
): Uint8Array {
  if (secretKey.length !== X25519_KEY_SIZE || peerPubKey.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }
  try {
    const ss = x25519.getSharedSecret(secretKey, peerPubKey);
    let allZero = true;
    for (let i = 0; i < ss.length; i++) {
      if (ss[i] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      throw new Error('ephemeral public key is weak or invalid');
    }
    return ss;
  } catch (err) {
    if (err instanceof Error && err.message === 'ephemeral public key is weak or invalid') {
      throw err;
    }
    throw new Error('ephemeral public key is weak or invalid');
  }
}

/**
 * Overwrite a byte slice with zeros in memory.
 */
export function zeroizeBytes(b: Uint8Array): void {
  b.fill(0);
}

/**
 * Compute the HMAC-SHA256 authentication tag over a challenge using k_pair.
 */
export async function computeTrustedMACTag(
  kPair: Uint8Array,
  domain: string,
  challenge: Uint8Array,
): Promise<string> {
  const data = concatBytes(utf8(domain), challenge);
  const tag = await hmacSha256(kPair, data);
  return bytesToHex(tag);
}

/**
 * Verify a MAC tag in constant time.
 */
export async function verifyTrustedMACTag(
  kPair: Uint8Array,
  domain: string,
  challenge: Uint8Array,
  tagHex: string,
): Promise<boolean> {
  const expected = await computeTrustedMACTag(kPair, domain, challenge);
  return constantTimeHexEqual(tagHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Derive pairwise authenticated directional session keys from ephemeral material and k_pair.
 * Note: Provides mutual authentication and replay resistance, but not forward secrecy against k_pair compromise.
 */
export async function deriveTrustedSessionKeys(
  kPair: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsInit: readonly string[],
  capsResp: readonly string[],
): Promise<TrustedSessionKeys> {
  if (kPair.length === 0) {
    throw new Error('k_pair required');
  }
  if (
    ephemPubInit.length !== TRUSTED_AUTH_EPHEMERAL_SIZE ||
    ephemPubResp.length !== TRUSTED_AUTH_EPHEMERAL_SIZE
  ) {
    throw new Error('invalid ephemeral public key size');
  }
  if (
    nonceInit.length !== TRUSTED_AUTH_NONCE_SIZE ||
    nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE
  ) {
    throw new Error('invalid nonce size');
  }

  const negotiated = intersectCapabilities(capsInit, capsResp);
  const capsHash = await hashCapabilities(negotiated);

  const ephemMix = concatBytes(ephemPubInit, ephemPubResp, nonceInit, nonceResp);
  const ikm = await hmacSha256(kPair, ephemMix);
  const salt = concatBytes(nonceInit, nonceResp);

  const kPairHash = await sha256(kPair);
  const transcript = await buildTrustedRespChallenge(
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    initId,
    respId,
    capsHash,
  );

  const infoMaster = concatBytes(utf8(DOMAIN_TRUSTED_MASTER), transcript);
  const sessionMaster = await hkdfSha256(ikm, salt, infoMaster, 32);

  const kI2R = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_INIT_TO_RESP_KEY),
    32,
  );
  const kR2I = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_RESP_TO_INIT_KEY),
    32,
  );

  return {
    sessionMaster,
    initiatorToResponderKey: kI2R,
    responderToInitiatorKey: kR2I,
    negotiatedCapabilities: negotiated,
  };
}

/**
 * Derive directional traffic keys using forward-secret ephemeral Diffie-Hellman and k_pair (ADR 0010).
 */
export async function deriveTrustedSessionKeysV3(
  kPair: Uint8Array,
  ssECDH: Uint8Array,
  ephemPubInit: Uint8Array,
  ephemPubResp: Uint8Array,
  nonceInit: Uint8Array,
  nonceResp: Uint8Array,
  initId: string,
  respId: string,
  capsInit: readonly string[],
  capsResp: readonly string[],
): Promise<TrustedSessionKeys> {
  if (kPair.length === 0) {
    throw new Error('k_pair required');
  }
  if (ssECDH.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }
  let allZero = true;
  for (let i = 0; i < ssECDH.length; i++) {
    if (ssECDH[i] !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw new Error('ephemeral public key is weak or invalid');
  }
  if (ephemPubInit.length !== X25519_KEY_SIZE || ephemPubResp.length !== X25519_KEY_SIZE) {
    throw new Error('invalid ephemeral public key size');
  }
  if (
    nonceInit.length !== TRUSTED_AUTH_NONCE_SIZE ||
    nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE
  ) {
    throw new Error('invalid nonce size');
  }

  const negotiated = intersectCapabilities(capsInit, capsResp);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);

  const transcript = buildTrustedTranscriptV3(
    kPairHash,
    ephemPubInit,
    ephemPubResp,
    nonceInit,
    nonceResp,
    initId,
    respId,
    capsHash,
  );
  const infoMaster = concatBytes(utf8(DOMAIN_TRUSTED_MASTER_3), transcript);

  const sessionMaster = await hkdfSha256(ssECDH, kPair, infoMaster, 32);

  const kI2R = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_INIT_TO_RESP_3),
    32,
  );
  const kR2I = await hkdfSha256(
    sessionMaster,
    new Uint8Array(0),
    utf8(DOMAIN_TRUSTED_RESP_TO_INIT_3),
    32,
  );

  return {
    sessionMaster,
    initiatorToResponderKey: kI2R,
    responderToInitiatorKey: kR2I,
    negotiatedCapabilities: negotiated,
  };
}

/**
 * Compute the confirmation tag for the session master.
 */
export async function computeTrustedConfirmTag(
  sessionMaster: Uint8Array,
  domain: string,
  deviceId: string,
): Promise<string> {
  const data = concatBytes(utf8(domain), utf8(deviceId));
  const tag = await hmacSha256(sessionMaster, data);
  return bytesToHex(tag);
}

/**
 * Verify the confirmation tag in constant time.
 */
export async function verifyTrustedConfirmTag(
  sessionMaster: Uint8Array,
  domain: string,
  deviceId: string,
  tagHex: string,
): Promise<boolean> {
  const expected = await computeTrustedConfirmTag(sessionMaster, domain, deviceId);
  return constantTimeHexEqual(tagHex.toLowerCase(), expected.toLowerCase());
}

/**
 * Create a signed and MAC-authenticated TrustedAuthInit message.
 */
export async function createTrustedAuthInit(
  id: DeviceIdentity,
  respDeviceId: string,
  credRef: string,
  kPair: Uint8Array,
  caps: string[],
  ephemPub?: Uint8Array,
  nonce?: Uint8Array,
  now?: Date | string,
  revocations?: RevocationRecord[],
): Promise<TrustedAuthInit> {
  const ephem =
    ephemPub && ephemPub.length === TRUSTED_AUTH_EPHEMERAL_SIZE
      ? ephemPub
      : randomBytes(TRUSTED_AUTH_EPHEMERAL_SIZE);
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);
  const tsStr =
    typeof now === 'string' ? now : (now || new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');

  const capsHash = await hashCapabilities(caps);
  const kPairHash = await sha256(kPair);

  const challenge = await buildTrustedInitChallenge(
    kPairHash,
    ephem,
    n,
    id.deviceId,
    respDeviceId,
    capsHash,
    tsStr,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_INIT_MAC, challenge);

  return {
    type: MSG_TRUSTED_AUTH_INIT,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION,
    initiator_device_id: id.deviceId,
    responder_device_id: respDeviceId,
    pair_credential_ref: credRef,
    ephemeral_pub: bytesToHex(ephem),
    nonce: bytesToHex(n),
    capabilities: caps,
    timestamp: tsStr,
    signature: bytesToHex(sig),
    auth_tag: tag,
    ...(revocations && revocations.length > 0 ? { revocations } : {}),
  };
}

/**
 * Validate format, clock skew, Ed25519 signature, and HMAC tag of a TrustedAuthInit.
 */
export async function verifyTrustedAuthInit(
  init: TrustedAuthInit,
  kPair: Uint8Array,
  initPubKey: Uint8Array,
  localDeviceId: string,
  now?: Date | string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (
    !init ||
    init.type !== MSG_TRUSTED_AUTH_INIT ||
    init.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION
  ) {
    throw new Error('invalid trusted-session message');
  }
  if (init.responder_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (!validateDeviceId(init.initiator_device_id)) {
    throw new Error('invalid device id format');
  }

  const expectedInitId = await deriveDeviceId(initPubKey);
  if (expectedInitId !== init.initiator_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ts = new Date(init.timestamp).getTime();
  if (Number.isNaN(ts)) {
    throw new Error('invalid trusted-session message');
  }
  const currentTime = (typeof now === 'string' ? new Date(now) : now || new Date()).getTime();
  const skew = Math.abs(currentTime - ts);
  if (skew > MAX_TRUSTED_TIMESTAMP_SKEW_MS) {
    throw new Error('trusted-session timestamp outside acceptable skew window');
  }

  const ephemPub = hexToBytes(init.ephemeral_pub);
  if (ephemPub.length !== TRUSTED_AUTH_EPHEMERAL_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const nonce = hexToBytes(init.nonce);
  if (nonce.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(init.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const capsHash = await hashCapabilities(init.capabilities);
  const kPairHash = await sha256(kPair);
  const challenge = await buildTrustedInitChallenge(
    kPairHash,
    ephemPub,
    nonce,
    init.initiator_device_id,
    init.responder_device_id,
    capsHash,
    init.timestamp,
  );

  const sigValid = verifyDeviceSignature(initPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_INIT_MAC,
    challenge,
    init.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemPub, nonce };
}

/**
 * Create a signed and MAC-authenticated TrustedAuthResponse message.
 */
export async function createTrustedAuthResponse(
  id: DeviceIdentity,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  caps: string[],
  ephemPub?: Uint8Array,
  nonce?: Uint8Array,
  revocations?: RevocationRecord[],
): Promise<TrustedAuthResponse> {
  const ephem =
    ephemPub && ephemPub.length === TRUSTED_AUTH_EPHEMERAL_SIZE
      ? ephemPub
      : randomBytes(TRUSTED_AUTH_EPHEMERAL_SIZE);
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);

  const ephemInit = hexToBytes(init.ephemeral_pub);
  const nonceInit = hexToBytes(init.nonce);

  const negotiated = intersectCapabilities(init.capabilities, caps);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);

  const challenge = await buildTrustedRespChallenge(
    kPairHash,
    ephemInit,
    ephem,
    nonceInit,
    n,
    init.initiator_device_id,
    id.deviceId,
    capsHash,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_RESP_MAC, challenge);

  return {
    type: MSG_TRUSTED_AUTH_RESPONSE,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION,
    status: 'accepted',
    responder_device_id: id.deviceId,
    ephemeral_pub: bytesToHex(ephem),
    nonce: bytesToHex(n),
    capabilities: caps,
    signature: bytesToHex(sig),
    auth_tag: tag,
    ...(revocations && revocations.length > 0 ? { revocations } : {}),
  };
}

/**
 * Validate format, Ed25519 signature, and HMAC tag of a TrustedAuthResponse.
 */
export async function verifyTrustedAuthResponse(
  resp: TrustedAuthResponse,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  respPubKey: Uint8Array,
  localDeviceId: string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (
    !resp ||
    resp.type !== MSG_TRUSTED_AUTH_RESPONSE ||
    resp.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION
  ) {
    throw new Error('invalid trusted-session message');
  }
  if (localDeviceId && init.initiator_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (resp.status !== 'accepted') {
    if (resp.status === 'revoked') {
      throw new Error('trusted peer device is revoked');
    }
    throw new Error('trusted session was rejected by peer');
  }
  if (resp.responder_device_id !== init.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const expectedRespId = await deriveDeviceId(respPubKey);
  if (expectedRespId !== resp.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ephemInit = hexToBytes(init.ephemeral_pub);
  const nonceInit = hexToBytes(init.nonce);

  if (!resp.ephemeral_pub || !resp.nonce || !resp.signature || !resp.auth_tag) {
    throw new Error('invalid trusted-session message');
  }

  const ephemResp = hexToBytes(resp.ephemeral_pub);
  if (ephemResp.length !== TRUSTED_AUTH_EPHEMERAL_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const nonceResp = hexToBytes(resp.nonce);
  if (nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(resp.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const negotiated = intersectCapabilities(init.capabilities, resp.capabilities || []);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);
  const challenge = await buildTrustedRespChallenge(
    kPairHash,
    ephemInit,
    ephemResp,
    nonceInit,
    nonceResp,
    init.initiator_device_id,
    resp.responder_device_id,
    capsHash,
  );

  const sigValid = verifyDeviceSignature(respPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_RESP_MAC,
    challenge,
    resp.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemResp, nonce: nonceResp };
}

/**
 * Create a TrustedAuthConfirm message.
 */
export async function createTrustedAuthConfirm(
  sessionMaster: Uint8Array,
  domain: string,
  localDeviceId: string,
  ready: boolean,
): Promise<TrustedAuthConfirm> {
  if (!ready) {
    return {
      type: MSG_TRUSTED_AUTH_CONFIRM,
      status: 'rejected',
    };
  }
  const tag = await computeTrustedConfirmTag(sessionMaster, domain, localDeviceId);
  return {
    type: MSG_TRUSTED_AUTH_CONFIRM,
    status: 'ready',
    auth_tag: tag,
  };
}

/**
 * Verify a TrustedAuthConfirm message.
 */
export async function verifyTrustedAuthConfirm(
  confirm: TrustedAuthConfirm,
  sessionMaster: Uint8Array,
  domain: string,
  peerDeviceId: string,
): Promise<void> {
  if (!confirm || confirm.type !== MSG_TRUSTED_AUTH_CONFIRM) {
    throw new Error('invalid trusted-session message');
  }
  if (confirm.status !== 'ready') {
    throw new Error('trusted session was rejected by peer');
  }
  if (
    !confirm.auth_tag ||
    !(await verifyTrustedConfirmTag(sessionMaster, domain, peerDeviceId, confirm.auth_tag))
  ) {
    throw new Error('trusted-session MAC tag verification failed');
  }
}

/**
 * Create a signed and MAC-authenticated TrustedAuthInit message under sendbeam/3.
 */
export async function createTrustedAuthInitV3(
  id: DeviceIdentity,
  respDeviceId: string,
  credRef: string,
  kPair: Uint8Array,
  caps: string[],
  ephemPub: Uint8Array,
  nonce?: Uint8Array,
  now?: Date | string,
  revocations?: RevocationRecord[],
): Promise<TrustedAuthInit> {
  if (kPair.length === 0) {
    throw new Error('k_pair required');
  }
  if (ephemPub.length !== X25519_KEY_SIZE) {
    throw new Error('invalid ephemeral public key size');
  }
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);
  const tsStr =
    typeof now === 'string' ? now : (now || new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');

  const capsHash = await hashCapabilities(caps);
  const kPairHash = await sha256(kPair);

  const challenge = buildTrustedInitChallengeV3(
    kPairHash,
    ephemPub,
    n,
    id.deviceId,
    respDeviceId,
    capsHash,
    tsStr,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_INIT_MAC_3, challenge);

  return {
    type: MSG_TRUSTED_AUTH_INIT,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION_V3,
    initiator_device_id: id.deviceId,
    responder_device_id: respDeviceId,
    pair_credential_ref: credRef,
    ephemeral_pub: bytesToHex(ephemPub),
    nonce: bytesToHex(n),
    capabilities: caps,
    timestamp: tsStr,
    signature: bytesToHex(sig),
    auth_tag: tag,
    ...(revocations && revocations.length > 0 ? { revocations } : {}),
  };
}

/**
 * Validate format, protocol version, clock skew, Ed25519 signature, and HMAC tag for sendbeam/3.
 */
export async function verifyTrustedAuthInitV3(
  init: TrustedAuthInit,
  kPair: Uint8Array,
  initPubKey: Uint8Array,
  localDeviceId: string,
  now?: Date | string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (!init || init.type !== MSG_TRUSTED_AUTH_INIT) {
    throw new Error('invalid trusted-session message');
  }
  if (init.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION_V3) {
    if (
      init.protocol_version === TRUSTED_AUTH_PROTOCOL_VERSION ||
      init.protocol_version === 'sendbeam/1'
    ) {
      throw new Error('trusted-session protocol downgrade forbidden');
    }
    throw new Error('invalid trusted-session message');
  }
  if (init.responder_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (!validateDeviceId(init.initiator_device_id)) {
    throw new Error('invalid device id format');
  }

  const expectedInitId = await deriveDeviceId(initPubKey);
  if (expectedInitId !== init.initiator_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ts = new Date(init.timestamp).getTime();
  if (Number.isNaN(ts)) {
    throw new Error('invalid trusted-session message');
  }
  const currentTime = (typeof now === 'string' ? new Date(now) : now || new Date()).getTime();
  const skew = Math.abs(currentTime - ts);
  if (skew > MAX_TRUSTED_TIMESTAMP_SKEW_MS) {
    throw new Error('trusted-session timestamp outside acceptable skew window');
  }

  const ephemPub = hexToBytes(init.ephemeral_pub);
  if (ephemPub.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }

  const nonce = hexToBytes(init.nonce);
  if (nonce.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(init.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const capsHash = await hashCapabilities(init.capabilities);
  const kPairHash = await sha256(kPair);
  const challenge = buildTrustedInitChallengeV3(
    kPairHash,
    ephemPub,
    nonce,
    init.initiator_device_id,
    init.responder_device_id,
    capsHash,
    init.timestamp,
  );

  const sigValid = verifyDeviceSignature(initPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_INIT_MAC_3,
    challenge,
    init.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemPub, nonce };
}

/**
 * Create a signed and MAC-authenticated TrustedAuthResponse under sendbeam/3.
 */
export async function createTrustedAuthResponseV3(
  id: DeviceIdentity,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  caps: string[],
  ephemPub: Uint8Array,
  nonce?: Uint8Array,
  revocations?: RevocationRecord[],
): Promise<TrustedAuthResponse> {
  if (kPair.length === 0) {
    throw new Error('k_pair required');
  }
  if (ephemPub.length !== X25519_KEY_SIZE) {
    throw new Error('invalid ephemeral public key size');
  }
  const n =
    nonce && nonce.length === TRUSTED_AUTH_NONCE_SIZE
      ? nonce
      : randomBytes(TRUSTED_AUTH_NONCE_SIZE);

  const ephemInit = hexToBytes(init.ephemeral_pub);
  if (ephemInit.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }
  const nonceInit = hexToBytes(init.nonce);
  if (nonceInit.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const negotiated = intersectCapabilities(init.capabilities, caps);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);

  const challenge = buildTrustedRespChallengeV3(
    kPairHash,
    ephemInit,
    ephemPub,
    nonceInit,
    n,
    init.initiator_device_id,
    id.deviceId,
    capsHash,
  );
  const sig = signDeviceMessage(id, challenge);
  const tag = await computeTrustedMACTag(kPair, DOMAIN_TRUSTED_RESP_MAC_3, challenge);

  return {
    type: MSG_TRUSTED_AUTH_RESPONSE,
    protocol_version: TRUSTED_AUTH_PROTOCOL_VERSION_V3,
    status: 'accepted',
    responder_device_id: id.deviceId,
    ephemeral_pub: bytesToHex(ephemPub),
    nonce: bytesToHex(n),
    capabilities: caps,
    signature: bytesToHex(sig),
    auth_tag: tag,
    ...(revocations && revocations.length > 0 ? { revocations } : {}),
  };
}

/**
 * Validate format, protocol version, Ed25519 signature, and HMAC tag for sendbeam/3.
 */
export async function verifyTrustedAuthResponseV3(
  resp: TrustedAuthResponse,
  init: TrustedAuthInit,
  kPair: Uint8Array,
  respPubKey: Uint8Array,
  localDeviceId: string,
): Promise<{ ephemeralPub: Uint8Array; nonce: Uint8Array }> {
  if (!resp || resp.type !== MSG_TRUSTED_AUTH_RESPONSE) {
    throw new Error('invalid trusted-session message');
  }
  if (resp.protocol_version !== TRUSTED_AUTH_PROTOCOL_VERSION_V3) {
    if (
      resp.protocol_version === TRUSTED_AUTH_PROTOCOL_VERSION ||
      resp.protocol_version === 'sendbeam/1'
    ) {
      throw new Error('trusted-session protocol downgrade forbidden');
    }
    throw new Error('invalid trusted-session message');
  }
  if (localDeviceId && init.initiator_device_id !== localDeviceId) {
    throw new Error('trusted-session peer device ID mismatch');
  }
  if (resp.status !== 'accepted') {
    if (resp.status === 'revoked') {
      throw new Error('trusted peer device is revoked');
    }
    throw new Error('trusted session was rejected by peer');
  }
  if (resp.responder_device_id !== init.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const expectedRespId = await deriveDeviceId(respPubKey);
  if (expectedRespId !== resp.responder_device_id) {
    throw new Error('trusted-session peer device ID mismatch');
  }

  const ephemInit = hexToBytes(init.ephemeral_pub);
  if (ephemInit.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }
  const nonceInit = hexToBytes(init.nonce);
  if (nonceInit.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  if (!resp.ephemeral_pub || !resp.nonce || !resp.signature || !resp.auth_tag) {
    throw new Error('invalid trusted-session message');
  }

  const ephemResp = hexToBytes(resp.ephemeral_pub);
  if (ephemResp.length !== X25519_KEY_SIZE) {
    throw new Error('ephemeral public key is weak or invalid');
  }

  const nonceResp = hexToBytes(resp.nonce);
  if (nonceResp.length !== TRUSTED_AUTH_NONCE_SIZE) {
    throw new Error('invalid trusted-session message');
  }

  const sigBytes = hexToBytes(resp.signature);
  if (sigBytes.length !== 64) {
    throw new Error('trusted-session signature verification failed');
  }

  const negotiated = intersectCapabilities(init.capabilities, resp.capabilities || []);
  const capsHash = await hashCapabilities(negotiated);
  const kPairHash = await sha256(kPair);
  const challenge = buildTrustedRespChallengeV3(
    kPairHash,
    ephemInit,
    ephemResp,
    nonceInit,
    nonceResp,
    init.initiator_device_id,
    resp.responder_device_id,
    capsHash,
  );

  const sigValid = verifyDeviceSignature(respPubKey, challenge, sigBytes);
  if (!sigValid) {
    throw new Error('trusted-session signature verification failed');
  }

  const macValid = await verifyTrustedMACTag(
    kPair,
    DOMAIN_TRUSTED_RESP_MAC_3,
    challenge,
    resp.auth_tag,
  );
  if (!macValid) {
    throw new Error('trusted-session MAC tag verification failed');
  }

  return { ephemeralPub: ephemResp, nonce: nonceResp };
}

/**
 * Create a TrustedAuthConfirm message for sendbeam/3.
 */
export function createTrustedAuthConfirmV3(
  sessionMaster: Uint8Array,
  domain: string,
  localDeviceId: string,
  ready: boolean,
): Promise<TrustedAuthConfirm> {
  return createTrustedAuthConfirm(sessionMaster, domain, localDeviceId, ready);
}

/**
 * Verify a TrustedAuthConfirm message for sendbeam/3.
 */
export function verifyTrustedAuthConfirmV3(
  confirm: TrustedAuthConfirm,
  sessionMaster: Uint8Array,
  domain: string,
  peerDeviceId: string,
): Promise<void> {
  return verifyTrustedAuthConfirm(confirm, sessionMaster, domain, peerDeviceId);
}

/**
 * Tracks recently seen (deviceId, nonce) tuples to detect replays within the timestamp skew window (ADR 0010).
 */
export class NonceReplayCache {
  private seen = new Map<string, number>();
  private readonly ttlMs: number;

  constructor(ttlMs: number = 10 * 60 * 1000) {
    this.ttlMs = ttlMs > 0 ? ttlMs : 10 * 60 * 1000;
  }

  checkAndRecord(deviceId: string, nonceHex: string, now?: Date | number | string): void {
    const currentTime =
      typeof now === 'number'
        ? now
        : typeof now === 'string'
          ? new Date(now).getTime()
          : now instanceof Date
            ? now.getTime()
            : Date.now();
    const cutoff = currentTime - this.ttlMs;

    for (const [k, exp] of this.seen.entries()) {
      if (exp < cutoff) {
        this.seen.delete(k);
      }
    }

    const key = `${deviceId}:${nonceHex}`;
    const exp = this.seen.get(key);
    if (exp !== undefined && exp >= cutoff) {
      throw new Error('trusted-session replay detected');
    }

    this.seen.set(key, currentTime);
  }
}
