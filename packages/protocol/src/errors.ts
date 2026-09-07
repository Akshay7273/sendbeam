/**
 * Stable machine-readable error classes shared with the Go wire package
 * (ADR 0002 — error taxonomy). Externally visible errors carry exactly one
 * class; UI and future automation key on it.
 */
export const ErrorCode = {
  Auth: 'AUTH',
  Protocol: 'PROTOCOL',
  Connection: 'CONNECTION',
  Relay: 'RELAY',
  RetryExhausted: 'RETRY_EXHAUSTED',
  Canceled: 'CANCELED',
  Storage: 'STORAGE',
  SourceIO: 'SOURCE_IO',
  DestIO: 'DEST_IO',
  Compat: 'COMPAT',
  Internal: 'INTERNAL',
} as const;
export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export const ERR_REVOCATION_UNAUTHORIZED = 'revocation record is unauthorized';
export const ERR_REVOCATION_SEQ_ROLLBACK = 'revocation sequence number rollback';
export const ERR_TRUSTED_PEER_REVOKED = 'trusted peer device is revoked';
export const ERR_UNKNOWN_REVOKER = 'revocation revoker is not an active trusted peer';
export const ERR_KEY_CONFLICT = 'device ID already paired with different public key';
export const ERR_LABEL_CONFLICT = 'a different trusted device already uses this label';
export const ERR_PADDING_REQUIRED = 'peer does not negotiate padding capability';
export const ERR_UNPADDED_FRAME = 'unpadded frame rejected by require-padding policy';
