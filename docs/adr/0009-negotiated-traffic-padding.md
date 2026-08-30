# ADR 0009: Negotiated Traffic Padding & Wire Privacy

**Status:** Accepted  
**Date:** 2026-08-30  
**Context:** SendBeam v1.7 Milestone V17-PR03  
**Deciders:** Core Engineering Team

---

## 1. Context & Problem Statement

In SendBeam v1.0–v1.6, all transfer data frames and signaling messages are encrypted with authenticated AES-256-GCM (`packages/wire/aead.go` and `packages/protocol/src/aead.ts`). While plaintext data and file contents are completely protected against passive and active network observers, the **ciphertext lengths** transmitted over WebSockets (relay path) and WebRTC DataChannels (direct path) directly mirror the unpadded plaintext chunk sizes.

As documented in `docs/threat-model.md` §Accepted Limitations:

> _File sizes and transfer structure are observable through frame lengths and packet volume._

An eavesdropper or intermediate relay can observe exact file chunk lengths, distinguishing between small metadata/control frames and identifying files with known exact byte lengths.

Our goal in v1.7 is to remove exact file size observability from the accepted limitations list via **negotiated, authenticated traffic padding**.

---

## 2. Design Decision

### 2.1 Capability Negotiation (`padding`)

Traffic padding is introduced as an opt-in, backwards-compatible negotiated feature:

- Capability identifier: `"padding"` (joins `"folders"`, `"resume"`, `"relay"`, `"archive"`, `"resumeauth"` in `Caps.Features`).
- Both peers must announce `"padding"` in their capabilities during session establishment; if either peer does not support or request padding, transfers fall back to unpadded framing (100% interoperability with v1.6 peers preserved).
- CLI flag: `--private` (or configuration setting `private_mode: true`).
- Web/Desktop UI: Privacy Mode toggle in settings.

### 2.2 Quantized Bucket Sizes

Plaintext frame payloads are padded to discrete power-of-two bucket sizes up to the maximum frame size (`MAX_FRAME_BYTES = 64 KiB`):

$$\text{BucketSizes} = \{ 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 \}$$

For any unpadded payload of length $L \le 65534$ bytes:

- The minimum required buffer length with a 2-byte prefix length is $L + 2$.
- The bucket size $B$ is the smallest power-of-2 in $\text{BucketSizes}$ such that $B \ge L + 2$ (clamped to minimum 256 bytes).

### 2.3 Padded Framing Format (Authenticated & Fail-Closed)

When padding is active, `FrameHeader.Flags` sets `FlagPadded = 0x01`:

```
FrameHeader (16 bytes, AAD):
[ Version (u8) | Type (u8) | Flags (u8 with FlagPadded=0x01) | Reserved (u8) ]
[ FileIdx (u16) | BlockIdx (u32) | FrameOff (u32) | Len = B (u16) ]

Plaintext Payload (B bytes before AES-GCM Seal):
[ UnpaddedLen (u16 big-endian) | Plaintext Data (L bytes) | Zero Padding (B - L - 2 bytes of 0x00) ]
```

1. **Header AAD Binding:** `Flags` and `Len` are authenticated as AES-GCM Additional Authenticated Data. Any tampering with the `FlagPadded` bit or frame length is detected by AEAD verification.
2. **Inner Authenticated Length:** `UnpaddedLen` ($L$) is sealed inside the AEAD ciphertext.
3. **Decryption & De-padding Verification (Fail-Closed):**
   - Receiver decrypts using AES-256-GCM.
   - If `header.Flags & FlagPadded != 0`:
     - Verify `len(decrypted) >= 2`.
     - Read $L = \text{Uint16BigEndian}(\text{decrypted}[0:2])$.
     - Verify $L + 2 \le \text{len}(\text{decrypted})$.
     - Verify all padding bytes $\text{decrypted}[2+L:]$ are strictly `0x00`.
     - If any check fails, reject fail-closed with `wire.ErrMalformedFrame`.
     - Extract original plaintext: $\text{decrypted}[2 : 2+L]$.
   - If `header.Flags & FlagPadded == 0`:
     - Return raw unpadded decrypted bytes (v1.6 compatibility).

---

## 3. Consequences & Guarantees

1. **Wire Privacy:** Eavesdroppers and relay servers observe only fixed bucket lengths ($256, 512, 1024, \dots, 65536$ bytes). Exact file sizes and chunk boundaries are obfuscated.
2. **Cryptographic Integrity:** Padding bytes and prefix lengths are fully authenticated under AES-256-GCM; any forged or corrupted padding is rejected immediately.
3. **Performance Overhead:** Padded framing incurs a modest 2-byte prefix overhead plus bucket quantization padding (typically $< 3\%$ on typical 16 KiB/64 KiB chunks).
4. **Honesty (Threat Model Scope):** Padding obscures size distribution; total aggregate transfer volume and coarse timing correlation remain observable. Documented precisely in `docs/threat-model.md`.
