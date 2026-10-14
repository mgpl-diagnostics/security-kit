/** HTTP header that carries the encoded `DeviceSignals` (see `encodeSignals`). */
export const SIGNALS_HEADER = "x-mgpl-signals";

/** Limits enforced by `decodeSignals`; anything larger or malformed is rejected. */
export const SIGNAL_LIMITS = {
  /** Encoded header value, in characters. */
  header: 2048,
  /** Any single string inside DeviceInfo, and `app`. */
  field: 64,
} as const;

/** Ids are 16 to 64 base64url characters (a UUID with or without dashes also fits). */
export const ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
/** Fingerprints are 32 lowercase hex characters. */
export const FINGERPRINT_PATTERN = /^[0-9a-f]{32}$/;
