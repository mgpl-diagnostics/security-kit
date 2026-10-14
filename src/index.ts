// "@mgpl-diagnostics/security-kit": the shared part. Runs in browsers, Node.js, workers and React Native.
export type { DeviceInfo, DeviceSignals } from "./shared/types";
export { FINGERPRINT_PATTERN, ID_PATTERN, SIGNAL_LIMITS, SIGNALS_HEADER } from "./shared/constants";
export { canonicalJson, constantTimeEqual, fromBase64Url, randomBytes, randomId, sha256Hex, toBase64Url } from "./shared/crypto";
export { decodeSignals, encodeSignals, parseDeviceInfo, parseSignals, signalHeaders } from "./shared/signals";
