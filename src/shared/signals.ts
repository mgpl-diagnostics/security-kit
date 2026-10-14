import { FINGERPRINT_PATTERN, ID_PATTERN, SIGNAL_LIMITS, SIGNALS_HEADER } from "./constants";
import { fromBase64Url, toBase64Url, utf8 } from "./crypto";
import type { DeviceInfo, DeviceSignals } from "./types";

/** Header value for `DeviceSignals`: base64url of their JSON. */
export function encodeSignals(signals: DeviceSignals): string {
  return toBase64Url(JSON.stringify(signals));
}

/** `{ "x-mgpl-signals": encodeSignals(signals) }`, ready to merge into request headers. */
export function signalHeaders(signals: DeviceSignals): Record<string, string> {
  return { [SIGNALS_HEADER]: encodeSignals(signals) };
}

// printable ASCII and common Unicode letters; no control characters, no angle brackets
const SAFE_TEXT = /^[^\u0000-\u001f\u007f<>]*$/;
const text = (v: unknown): string | null => (typeof v === "string" && v.length <= SIGNAL_LIMITS.field && SAFE_TEXT.test(v) ? v : null);

/** Checks an untrusted value and returns clean `DeviceInfo`, or null if any field is wrong. */
export function parseDeviceInfo(v: unknown): DeviceInfo | null {
  if (!v || typeof v !== "object") return null;
  const d = v as Record<string, unknown>;
  const os = text(d.os), browser = text(d.browser), browserVersion = text(d.browserVersion);
  const language = text(d.language), timezone = text(d.timezone), screen = text(d.screen);
  if (os === null || browser === null || browserVersion === null || language === null || timezone === null || screen === null) return null;
  if (typeof d.mobile !== "boolean") return null;
  return { os, browser, browserVersion, mobile: d.mobile, language, timezone, screen };
}

/** Checks an untrusted object and returns clean `DeviceSignals` (unknown keys dropped), or null. */
export function parseSignals(v: unknown): DeviceSignals | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const s = v as Record<string, unknown>;
  if (s.v !== 1) return null;
  if (typeof s.deviceId !== "string" || !ID_PATTERN.test(s.deviceId)) return null;
  if (typeof s.tabId !== "string" || !ID_PATTERN.test(s.tabId)) return null;
  if (typeof s.fingerprint !== "string" || !FINGERPRINT_PATTERN.test(s.fingerprint)) return null;
  const device = parseDeviceInfo(s.device);
  if (!device) return null;
  let app: string | undefined;
  if (s.app !== undefined) {
    const a = text(s.app);
    if (a === null) return null;
    app = a;
  }
  return { v: 1, deviceId: s.deviceId, tabId: s.tabId, fingerprint: s.fingerprint, device, ...(app !== undefined ? { app } : {}) };
}

/** Decodes and validates a header value; null when missing, too long or malformed. Never throws. */
export function decodeSignals(value: string | null | undefined): DeviceSignals | null {
  if (typeof value !== "string" || !value || value.length > SIGNAL_LIMITS.header) return null;
  const bytes = fromBase64Url(value.trim());
  if (!bytes) return null;
  try {
    return parseSignals(JSON.parse(utf8.decode(bytes)));
  } catch {
    return null;
  }
}
