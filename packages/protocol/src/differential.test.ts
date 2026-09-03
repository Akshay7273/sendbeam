/**
 * Differential cross-language parity test suite (Go <-> TypeScript).
 *
 * Verifies byte-for-byte serialization, canonical challenge construction,
 * parsing invariants, and fail-closed behavior against Go-generated vectors.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from './bytes.js';
import {
  decodeFrameHeader,
  encodeFrameHeader,
  padBucketSize,
  padPayload,
  unpadPayload,
} from './frame.js';
import {
  FrameType,
  type FrameHeader,
  type Manifest,
  type Ack,
  type Nack,
  type Control,
} from './transfer.js';
import { decodeControl, encodeControl } from './transfer-messages.js';
import {
  buildRevocationChallenge,
  validateRevocationRecord,
  verifyRevocation,
  type RevocationRecord,
} from './revocation.js';
import {
  buildPairingRequestChallenge,
  buildPairingResponseChallenge,
  computePairingConfirmTag,
  derivePairCredential,
  verifyPairingConfirmTag,
} from './pairing.js';
import {
  buildTrustedInitChallenge,
  buildTrustedRespChallenge,
  computeTrustedConfirmTag,
  DOMAIN_TRUSTED_CONFIRM_INIT,
  hashCapabilities,
  intersectCapabilities,
} from './trusted-auth.js';
import { normalizeCode, parseCode } from './words.js';
import { normalizeTransferPath } from './safe-path.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { deriveDeviceId } from './identity.js';

interface DifferentialRecord {
  category: string;
  case_id: string;
  seed: number;
  desc: string;
  payload: Record<string, unknown>;
}

function loadGoVectors(): DifferentialRecord[] {
  const url = new URL('../../wire/testdata/diffgen-go.jsonl', import.meta.url);
  const raw = readFileSync(fileURLToPath(url), 'utf8');
  return raw
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as DifferentialRecord);
}

describe('differential parity: Go -> TS', { timeout: 30_000 }, () => {
  const vectors = loadGoVectors();

  const byCat = new Map<string, DifferentialRecord[]>();
  for (const v of vectors) {
    if (!byCat.has(v.category)) {
      byCat.set(v.category, []);
    }
    byCat.get(v.category)!.push(v);
  }

  it('verifies frame_header codecs agree with Go', () => {
    const list = byCat.get('frame_header') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        header: {
          Version: number;
          Type: number;
          Flags: number;
          FileIdx: number;
          BlockIdx: number;
          FrameOff: number;
          Len: number;
        };
        encoded_hex: string;
      };
      const buf = hexToBytes(p.encoded_hex);

      // 1. Decode Go bytes in TS
      const decoded = decodeFrameHeader(buf);
      expect(decoded.version, `${item.case_id} (seed=${item.seed}) version`).toBe(p.header.Version);
      expect(decoded.type, `${item.case_id} (seed=${item.seed}) type`).toBe(p.header.Type);
      expect(decoded.flags, `${item.case_id} (seed=${item.seed}) flags`).toBe(p.header.Flags);
      expect(decoded.fileIdx, `${item.case_id} (seed=${item.seed}) fileIdx`).toBe(p.header.FileIdx);
      expect(decoded.blockIdx, `${item.case_id} (seed=${item.seed}) blockIdx`).toBe(
        p.header.BlockIdx,
      );
      expect(decoded.frameOff, `${item.case_id} (seed=${item.seed}) frameOff`).toBe(
        p.header.FrameOff,
      );
      expect(decoded.len, `${item.case_id} (seed=${item.seed}) len`).toBe(p.header.Len);

      // 2. Re-encode in TS and assert exact byte match with Go
      const tsHeader: FrameHeader = {
        version: p.header.Version,
        type: p.header.Type,
        flags: p.header.Flags,
        fileIdx: p.header.FileIdx,
        blockIdx: p.header.BlockIdx,
        frameOff: p.header.FrameOff,
        len: p.header.Len,
      };
      const reEncoded = encodeFrameHeader(tsHeader);
      expect(bytesToHex(reEncoded), `${item.case_id} (seed=${item.seed}) re-encoded`).toBe(
        p.encoded_hex,
      );
    }
  });

  it('verifies padding codec agrees with Go', () => {
    const list = byCat.get('padding') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        plaintext_hex: string;
        bucket_size: number;
        padded_hex: string;
        corrupted?: boolean;
      };
      const plain = hexToBytes(p.plaintext_hex);
      const padded = hexToBytes(p.padded_hex);

      if (p.corrupted) {
        expect(
          () => unpadPayload(padded),
          `${item.case_id} (seed=${item.seed}) should throw on corrupted padding`,
        ).toThrow();
        continue;
      }

      // 1. Bucket size matches
      expect(padBucketSize(plain.length), `${item.case_id} (seed=${item.seed}) bucket size`).toBe(
        p.bucket_size,
      );

      // 2. Padding produces identical buffer
      const tsPadded = padPayload(plain);
      expect(bytesToHex(tsPadded), `${item.case_id} (seed=${item.seed}) padded hex`).toBe(
        p.padded_hex,
      );

      // 3. Unpadding recovers original plaintext
      const tsUnpadded = unpadPayload(padded);
      expect(bytesToHex(tsUnpadded), `${item.case_id} (seed=${item.seed}) unpadded hex`).toBe(
        p.plaintext_hex,
      );
    }
  });

  it('verifies control message encodings agree with Go', () => {
    const list = byCat.get('control') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        msg_type: string;
        json_str: string;
        encoded_hex: string;
        structured: { type: number; [k: string]: unknown };
      };
      const buf = hexToBytes(p.encoded_hex);

      // 1. Decode Go JSON in TS
      const decoded = decodeControl(buf);
      expect(decoded.type, `${item.case_id} (seed=${item.seed}) message type`).toBe(
        p.structured.type,
      );

      // 2. Re-encode in TS and compare JSON
      const reEncoded = encodeControl(decoded);
      expect(
        JSON.parse(new TextDecoder().decode(reEncoded)),
        `${item.case_id} (seed=${item.seed}) JSON shape`,
      ).toEqual(p.structured);
    }
  });

  it('verifies revocation challenges and signatures agree with Go', async () => {
    const list = byCat.get('revocation') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        revoker_id: string;
        revoked_id: string;
        seq: number;
        timestamp: string;
        challenge_hex: string;
        signature_hex: string;
        public_key_hex: string;
      };

      // 1. Challenge byte-for-byte identical
      const chal = buildRevocationChallenge(p.revoker_id, p.revoked_id, p.seq, p.timestamp);
      expect(bytesToHex(chal), `${item.case_id} (seed=${item.seed}) challenge hex`).toBe(
        p.challenge_hex,
      );

      // 2. Signature verification
      const rec: RevocationRecord = {
        revoker_device_id: p.revoker_id,
        revoked_device_id: p.revoked_id,
        seq: p.seq,
        timestamp: p.timestamp,
        signature: p.signature_hex,
      };
      const pub = hexToBytes(p.public_key_hex);
      const ok = await verifyRevocation(rec, pub);
      expect(ok, `${item.case_id} (seed=${item.seed}) verifyRevocation`).toBe(true);
      expect(
        () => validateRevocationRecord(rec),
        `${item.case_id} (seed=${item.seed}) validateRevocationRecord`,
      ).not.toThrow();
    }
  });

  it('verifies pairing challenges, HKDF derivations, and tags agree with Go', async () => {
    const list = byCat.get('pairing') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        master_key_hex: string;
        req_nonce_hex: string;
        resp_nonce_hex: string;
        device_id_a: string;
        pub_a_hex: string;
        device_id_b: string;
        pub_b_hex: string;
        req_challenge_hex: string;
        resp_challenge_hex: string;
        k_pair_hex: string;
        cred_ref: string;
        confirm_peer_id: string;
        confirm_tag_hex: string;
      };
      const masterKey = hexToBytes(p.master_key_hex);
      const reqNonce = hexToBytes(p.req_nonce_hex);
      const respNonce = hexToBytes(p.resp_nonce_hex);
      const pubA = hexToBytes(p.pub_a_hex);
      const pubB = hexToBytes(p.pub_b_hex);

      // 1. Request challenge
      const reqChal = await buildPairingRequestChallenge(masterKey, reqNonce, p.device_id_a);
      expect(bytesToHex(reqChal), `${item.case_id} (seed=${item.seed}) req challenge`).toBe(
        p.req_challenge_hex,
      );

      // 2. Response challenge
      const respChal = await buildPairingResponseChallenge(
        masterKey,
        reqNonce,
        respNonce,
        p.device_id_b,
      );
      expect(bytesToHex(respChal), `${item.case_id} (seed=${item.seed}) resp challenge`).toBe(
        p.resp_challenge_hex,
      );

      // 3. Credential derivation
      const { kPair, credRef } = await derivePairCredential(
        masterKey,
        reqNonce,
        respNonce,
        pubA,
        pubB,
      );
      expect(bytesToHex(kPair), `${item.case_id} (seed=${item.seed}) k_pair`).toBe(p.k_pair_hex);
      expect(credRef, `${item.case_id} (seed=${item.seed}) cred_ref`).toBe(p.cred_ref);

      // 4. Confirm tag
      const confirmTag = await computePairingConfirmTag(kPair, p.confirm_peer_id);
      expect(confirmTag, `${item.case_id} (seed=${item.seed}) confirm tag`).toBe(p.confirm_tag_hex);
      const tagOk = await verifyPairingConfirmTag(kPair, p.confirm_peer_id, p.confirm_tag_hex);
      expect(tagOk, `${item.case_id} (seed=${item.seed}) verify confirm tag`).toBe(true);
    }
  });

  it('verifies trusted auth capabilities, challenges, and tags agree with Go', async () => {
    const list = byCat.get('trusted_auth') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        capabilities_a: string[];
        capabilities_b: string[];
        hash_a_hex: string;
        hash_b_hex: string;
        intersect_result: string[];
        k_pair_hash_hex: string;
        initiator_id: string;
        responder_id: string;
        ephemeral_pub_hex: string;
        nonce_hex: string;
        ephem_resp_pub_hex: string;
        nonce_resp_hex: string;
        timestamp: string;
        init_challenge_hex: string;
        resp_challenge_hex: string;
        confirm_tag_hex: string;
      };

      // 1. Capability hashing
      const hashA = await hashCapabilities(p.capabilities_a);
      expect(bytesToHex(hashA), `${item.case_id} (seed=${item.seed}) hash caps`).toBe(p.hash_a_hex);

      // 2. Capability intersection
      const intersect = intersectCapabilities(p.capabilities_a, p.capabilities_b);
      expect(intersect, `${item.case_id} (seed=${item.seed}) intersect caps`).toEqual(
        p.intersect_result,
      );

      // 3. Challenges
      const kPairHash = hexToBytes(p.k_pair_hash_hex);
      const ephemInit = hexToBytes(p.ephemeral_pub_hex);
      const nonceInit = hexToBytes(p.nonce_hex);
      const hashABytes = hexToBytes(p.hash_a_hex);
      const initChal = await buildTrustedInitChallenge(
        kPairHash,
        ephemInit,
        nonceInit,
        p.initiator_id,
        p.responder_id,
        hashABytes,
        p.timestamp,
      );
      expect(bytesToHex(initChal), `${item.case_id} (seed=${item.seed}) init challenge`).toBe(
        p.init_challenge_hex,
      );

      const ephemResp = hexToBytes(p.ephem_resp_pub_hex);
      const nonceResp = hexToBytes(p.nonce_resp_hex);
      const hashBBytes = hexToBytes(p.hash_b_hex);
      const respChal = await buildTrustedRespChallenge(
        kPairHash,
        ephemInit,
        ephemResp,
        nonceInit,
        nonceResp,
        p.initiator_id,
        p.responder_id,
        hashBBytes,
      );
      expect(bytesToHex(respChal), `${item.case_id} (seed=${item.seed}) resp challenge`).toBe(
        p.resp_challenge_hex,
      );
    }
  });

  it('verifies word code normalization and parsing agree with Go', () => {
    const list = byCat.get('words') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        raw_input: string;
        normalized: string;
        is_valid_code: boolean;
        room: number;
        words: string;
      };

      // 1. Normalization
      const norm = normalizeCode(p.raw_input);
      expect(norm, `${item.case_id} (seed=${item.seed}) normalized`).toBe(p.normalized);

      // 2. Parsing
      if (p.is_valid_code) {
        const parsed = parseCode(p.raw_input);
        expect(parsed.room, `${item.case_id} (seed=${item.seed}) parsed room`).toBe(p.room);
        expect(parsed.words, `${item.case_id} (seed=${item.seed}) parsed words`).toBe(p.words);
      } else {
        expect(
          () => parseCode(p.raw_input),
          `${item.case_id} (seed=${item.seed}) parse should throw on invalid input`,
        ).toThrow();
      }
    }
  });

  it('verifies safe path normalization agrees with Go', () => {
    const list = byCat.get('safe_path') || [];
    expect(list.length).toBeGreaterThan(0);

    for (const item of list) {
      const p = item.payload as unknown as {
        raw_path: string;
        normalized_path: string;
        is_valid: boolean;
      };

      if (p.is_valid) {
        const norm = normalizeTransferPath(p.raw_path);
        expect(norm, `${item.case_id} (seed=${item.seed}) normalized path`).toBe(p.normalized_path);
      } else {
        expect(
          () => normalizeTransferPath(p.raw_path),
          `${item.case_id} (seed=${item.seed}) safe path should throw on invalid path`,
        ).toThrow();
      }
    }
  });
});

describe('differential parity: TS generator & export', () => {
  it('generates TS differential vectors and writes to packages/wire/testdata/diffgen-ts.jsonl', async () => {
    const tsRecords = await generateTsDifferentialVectors(100, 1337);
    expect(tsRecords.length).toBeGreaterThan(500);

    const tsUrl = new URL('../../wire/testdata/diffgen-ts.jsonl', import.meta.url);
    const content = tsRecords.map((r) => JSON.stringify(r)).join('\n') + '\n';
    writeFileSync(fileURLToPath(tsUrl), content, 'utf8');
  });
});

// Deterministic PRNG for TS generator
function createRng(seed: number) {
  let s = seed >>> 0;
  return {
    next(): number {
      s = (s + 0x6d2b79f5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    },
    int(max: number): number {
      return Math.floor(this.next() * max);
    },
    bytes(len: number): Uint8Array {
      const b = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        b[i] = this.int(256);
      }
      return b;
    },
  };
}

async function generateTsDifferentialVectors(
  count: number,
  seed: number,
): Promise<DifferentialRecord[]> {
  const rng = createRng(seed);
  const records: DifferentialRecord[] = [];
  const emit = (
    category: string,
    case_id: string,
    desc: string,
    payload: Record<string, unknown>,
  ) => {
    records.push({ category, case_id, seed, desc, payload });
  };

  // 1. Frame Headers
  const boundaries = [
    { version: 1, type: 1, flags: 0, fileIdx: 0, blockIdx: 0, frameOff: 0, len: 0 },
    { version: 1, type: 3, flags: 1, fileIdx: 1, blockIdx: 1, frameOff: 1024, len: 16384 },
    {
      version: 1,
      type: 3,
      flags: 2,
      fileIdx: 65535,
      blockIdx: 4294967295,
      frameOff: 4294967295,
      len: 65535,
    },
    {
      version: 255,
      type: 255,
      flags: 255,
      fileIdx: 65535,
      blockIdx: 4294967295,
      frameOff: 4294967295,
      len: 65535,
    },
  ];
  for (let i = 0; i < boundaries.length; i++) {
    const h = boundaries[i]!;
    const encoded = encodeFrameHeader(h);
    emit('frame_header', `fh_edge_${i}`, 'boundary frame header', {
      header: {
        Version: h.version,
        Type: h.type,
        Flags: h.flags,
        FileIdx: h.fileIdx,
        BlockIdx: h.blockIdx,
        FrameOff: h.frameOff,
        Len: h.len,
      },
      encoded_hex: bytesToHex(encoded),
    });
  }

  for (let i = 0; i < count; i++) {
    const h = {
      version: rng.int(256),
      type: rng.int(256),
      flags: rng.int(256),
      fileIdx: rng.int(65536),
      blockIdx: rng.int(4294967296),
      frameOff: rng.int(4294967296),
      len: rng.int(65536),
    };
    const encoded = encodeFrameHeader(h);
    emit('frame_header', `fh_rand_${i}`, 'randomized frame header', {
      header: {
        Version: h.version,
        Type: h.type,
        Flags: h.flags,
        FileIdx: h.fileIdx,
        BlockIdx: h.blockIdx,
        FrameOff: h.frameOff,
        Len: h.len,
      },
      encoded_hex: bytesToHex(encoded),
    });
  }

  // 2. Padding
  const boundaryLens = [0, 1, 253, 254, 255, 510, 511, 1022, 1023, 2046, 2047];
  for (let i = 0; i < boundaryLens.length; i++) {
    const l = boundaryLens[i]!;
    const plain = new Uint8Array(l);
    for (let j = 0; j < l; j++) plain[j] = (j + i) % 256;
    const bucket = padBucketSize(l);
    const padded = padPayload(plain);
    emit('padding', `pad_boundary_${i}`, `boundary length ${l}`, {
      plaintext_hex: bytesToHex(plain),
      bucket_size: bucket,
      padded_hex: bytesToHex(padded),
    });
  }

  for (let i = 0; i < count; i++) {
    const l = rng.int(256);
    const plain = rng.bytes(l);
    const bucket = padBucketSize(l);
    const padded = padPayload(plain);
    emit('padding', `pad_rand_${i}`, `random length ${l}`, {
      plaintext_hex: bytesToHex(plain),
      bucket_size: bucket,
      padded_hex: bytesToHex(padded),
    });
  }

  for (let i = 0; i < 20; i++) {
    const plain = new Uint8Array(200);
    const padded = padPayload(plain);
    const corruptIdx = 2 + plain.length + 1 + rng.int(padded.length - (2 + plain.length + 1));
    padded[corruptIdx] = 1 + rng.int(255);
    emit('padding', `pad_corrupt_byte_${i}`, 'non-zero padding byte', {
      plaintext_hex: bytesToHex(plain),
      bucket_size: padded.length,
      padded_hex: bytesToHex(padded),
      corrupted: true,
      corrupt_type: 'non_zero_padding',
    });
  }

  // 3. Control
  for (let i = 0; i < Math.floor(count / 4); i++) {
    const manifest: Manifest = {
      type: FrameType.Manifest,
      transferId: `tid-${i.toString(16).padStart(8, '0')}`,
      files: [
        {
          idx: 0,
          name: 'test.txt',
          size: 100,
          mime: 'text/plain',
          lastModified: 1700000000000,
          blockSize: 1048576,
          blocks: 1,
          fileDigest: '0'.repeat(64),
        },
      ],
      totalSize: 100,
    };
    const encoded = encodeControl(manifest);
    emit('control', `ctrl_manifest_${i}`, 'manifest message', {
      msg_type: 'manifest',
      json_str: new TextDecoder().decode(encoded),
      encoded_hex: bytesToHex(encoded),
      structured: manifest,
    });
  }

  for (let i = 0; i < Math.floor(count / 4); i++) {
    const ack: Ack = {
      type: FrameType.Ack,
      fileIdx: rng.int(10),
      blockIdx: rng.int(500),
    };
    const encoded = encodeControl(ack);
    emit('control', `ctrl_ack_${i}`, 'block ack message', {
      msg_type: 'ack',
      json_str: new TextDecoder().decode(encoded),
      encoded_hex: bytesToHex(encoded),
      structured: ack,
    });
  }

  for (let i = 0; i < Math.floor(count / 4); i++) {
    const nack: Nack = {
      type: FrameType.Nack,
      fileIdx: rng.int(10),
      blockIdx: rng.int(500),
      reason: i % 2 === 1 ? 'timeout' : 'missing',
    };
    const encoded = encodeControl(nack);
    emit('control', `ctrl_nack_${i}`, 'file nack message', {
      msg_type: 'nack',
      json_str: new TextDecoder().decode(encoded),
      encoded_hex: bytesToHex(encoded),
      structured: nack,
    });
  }

  for (let i = 0; i < Math.floor(count / 4); i++) {
    const ctrl: Control = {
      type: FrameType.Control,
      op: i % 2 === 1 ? 'resume' : 'pause',
    };
    const encoded = encodeControl(ctrl);
    emit('control', `ctrl_pause_${i}`, 'control op message', {
      msg_type: 'control',
      json_str: new TextDecoder().decode(encoded),
      encoded_hex: bytesToHex(encoded),
      structured: ctrl,
    });
  }

  // 4. Revocation
  for (let i = 0; i < count; i++) {
    const seedA = rng.bytes(32);
    const seedB = rng.bytes(32);
    const pubA = ed25519.getPublicKey(seedA);
    const pubB = ed25519.getPublicKey(seedB);
    const revokerId = await deriveDeviceId(pubA);
    const revokedId = await deriveDeviceId(pubB);
    const seq = 1 + rng.int(100000);
    const ts = new Date(Date.UTC(2026, 7, 15, 10, i % 60, 0)).toISOString();

    const chal = buildRevocationChallenge(revokerId, revokedId, seq, ts);
    const sig = ed25519.sign(chal, seedA);

    const record: RevocationRecord = {
      revoker_device_id: revokerId,
      revoked_device_id: revokedId,
      seq,
      timestamp: ts,
      signature: bytesToHex(sig),
    };

    emit('revocation', `revoc_${i}`, 'ed25519 revocation challenge and signature', {
      revoker_id: revokerId,
      revoked_id: revokedId,
      seq,
      timestamp: ts,
      challenge_hex: bytesToHex(chal),
      signature_hex: bytesToHex(sig),
      public_key_hex: bytesToHex(pubA),
      record,
      valid: true,
    });
  }

  // 5. Pairing
  for (let i = 0; i < count; i++) {
    const masterKey = rng.bytes(32);
    const reqNonce = rng.bytes(32);
    const respNonce = rng.bytes(32);
    const seedA = rng.bytes(32);
    const seedB = rng.bytes(32);
    const pubA = ed25519.getPublicKey(seedA);
    const pubB = ed25519.getPublicKey(seedB);
    const devA = await deriveDeviceId(pubA);
    const devB = await deriveDeviceId(pubB);

    const reqChal = await buildPairingRequestChallenge(masterKey, reqNonce, devA);
    const respChal = await buildPairingResponseChallenge(masterKey, reqNonce, respNonce, devB);
    const { kPair, credRef } = await derivePairCredential(
      masterKey,
      reqNonce,
      respNonce,
      pubA,
      pubB,
    );
    const confirmTag = await computePairingConfirmTag(kPair, devB);

    emit('pairing', `pair_${i}`, 'pairing challenges and derivations', {
      master_key_hex: bytesToHex(masterKey),
      req_nonce_hex: bytesToHex(reqNonce),
      resp_nonce_hex: bytesToHex(respNonce),
      device_id_a: devA,
      pub_a_hex: bytesToHex(pubA),
      device_id_b: devB,
      pub_b_hex: bytesToHex(pubB),
      req_challenge_hex: bytesToHex(reqChal),
      resp_challenge_hex: bytesToHex(respChal),
      k_pair_hex: bytesToHex(kPair),
      cred_ref: credRef,
      confirm_peer_id: devB,
      confirm_tag_hex: confirmTag,
    });
  }

  // 6. Trusted Auth
  const allCaps = ['streaming', 'resume', 'lan-sync', 'padding', 'e2ee', 'blob-store'];
  for (let i = 0; i < count; i++) {
    const capsA = sampleCapsLocal(rng, allCaps);
    const capsB = sampleCapsLocal(rng, allCaps);
    const hashA = await hashCapabilities(capsA);
    const hashB = await hashCapabilities(capsB);
    const intersect = intersectCapabilities(capsA, capsB);

    const kPairHash = rng.bytes(32);
    const ephemInit = rng.bytes(32);
    const ephemResp = rng.bytes(32);
    const nonceInit = rng.bytes(32);
    const nonceResp = rng.bytes(32);
    const initId = `dev-${rng.int(0xffffffff).toString(16).padStart(8, '0')}`;
    const respId = `dev-${rng.int(0xffffffff).toString(16).padStart(8, '0')}`;
    const ts = new Date(Date.UTC(2026, 7, 15, 12, 0, i % 60)).toISOString();

    const initChal = await buildTrustedInitChallenge(
      kPairHash,
      ephemInit,
      nonceInit,
      initId,
      respId,
      hashA,
      ts,
    );
    const respChal = await buildTrustedRespChallenge(
      kPairHash,
      ephemInit,
      ephemResp,
      nonceInit,
      nonceResp,
      initId,
      respId,
      hashB,
    );
    const sessionMaster = rng.bytes(32);
    const confirmTag = await computeTrustedConfirmTag(
      sessionMaster,
      DOMAIN_TRUSTED_CONFIRM_INIT,
      respId,
    );

    emit('trusted_auth', `ta_${i}`, 'trusted auth capabilities and challenges', {
      capabilities_a: capsA,
      capabilities_b: capsB,
      hash_a_hex: bytesToHex(hashA),
      hash_b_hex: bytesToHex(hashB),
      intersect_result: intersect,
      k_pair_hash_hex: bytesToHex(kPairHash),
      initiator_id: initId,
      responder_id: respId,
      ephemeral_pub_hex: bytesToHex(ephemInit),
      nonce_hex: bytesToHex(nonceInit),
      ephem_resp_pub_hex: bytesToHex(ephemResp),
      nonce_resp_hex: bytesToHex(nonceResp),
      timestamp: ts,
      init_challenge_hex: bytesToHex(initChal),
      resp_challenge_hex: bytesToHex(respChal),
      confirm_tag_hex: confirmTag,
    });
  }

  // 7. Words
  const validSamples = [
    '42-brave-otter',
    '1001-ant-ape',
    '7-falcon-wolf-deer',
    '  99 - CAT - DOG  ',
    '500_owl.fox',
  ];
  for (let i = 0; i < validSamples.length; i++) {
    const s = validSamples[i]!;
    const norm = normalizeCode(s);
    let parsedRoom = 0;
    let parsedWords = '';
    let valid = false;
    try {
      const p = parseCode(s);
      parsedRoom = p.room;
      parsedWords = p.words;
      valid = true;
    } catch {
      valid = false;
    }
    emit('words', `words_sample_${i}`, 'standard word code', {
      raw_input: s,
      normalized: norm,
      is_valid_code: valid,
      room: parsedRoom,
      words: parsedWords,
    });
  }

  for (let i = 0; i < count; i++) {
    const room = 1 + rng.int(999999);
    const raw = `${room}-word${rng.int(100)}-word${rng.int(100)}`;
    const norm = normalizeCode(raw);
    const p = parseCode(raw);
    emit('words', `words_rand_${i}`, 'random word code', {
      raw_input: raw,
      normalized: norm,
      is_valid_code: true,
      room: p.room,
      words: p.words,
    });
  }

  // 8. Safe Paths
  const validPaths = [
    'file.txt',
    'docs/readme.md',
    'a/b/c/d/e.png',
    'folder/file with spaces (1).pdf',
  ];
  for (let i = 0; i < validPaths.length; i++) {
    const p = validPaths[i]!;
    const norm = normalizeTransferPath(p);
    emit('safe_path', `sp_valid_${i}`, 'valid path', {
      raw_path: p,
      normalized_path: norm,
      is_valid: true,
    });
  }

  const invalidPaths = ['', '/etc/passwd', '..\\secret', 'con.txt', 'aux', 'trailing-space '];
  for (let i = 0; i < invalidPaths.length; i++) {
    const p = invalidPaths[i]!;
    let norm = '';
    let valid = false;
    try {
      norm = normalizeTransferPath(p);
      valid = true;
    } catch {
      valid = false;
    }
    emit('safe_path', `sp_invalid_${i}`, 'invalid path', {
      raw_path: p,
      normalized_path: norm,
      is_valid: valid,
    });
  }

  return records;
}

function sampleCapsLocal(rng: ReturnType<typeof createRng>, pool: string[]): string[] {
  const n = 1 + rng.int(pool.length);
  const copy = [...pool];
  const res: string[] = [];
  for (let i = 0; i < n; i++) {
    const idx = rng.int(copy.length);
    res.push(copy.splice(idx, 1)[0]!);
  }
  return res;
}
