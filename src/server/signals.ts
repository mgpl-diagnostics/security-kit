import { createHash, timingSafeEqual } from "node:crypto";
import { SIGNALS_HEADER } from "../shared/constants";
import { decodeSignals } from "../shared/signals";
import type { DeviceInfo, DeviceSignals } from "../shared/types";

/** Request headers as Fetch `Headers`, Node's `IncomingHttpHeaders`, or a plain record. */
export type HeaderSource = Headers | { get(name: string): string | null } | Record<string, string | string[] | undefined>;

/** One header value (the first, when repeated); lookup is case-insensitive for records. */
export function headerValue(headers: HeaderSource | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === "function") return (headers as { get(n: string): string | null }).get(name) ?? undefined;
  const rec = headers as Record<string, string | string[] | undefined>;
  const lower = name.toLowerCase();
  const key = lower in rec ? lower : Object.keys(rec).find((k) => k.toLowerCase() === lower);
  const v = key === undefined ? undefined : rec[key];
  return Array.isArray(v) ? v[0] : v;
}

/** The request's `DeviceSignals`, or null when the header is missing or invalid. Never throws. */
export function readSignals(headers: HeaderSource | undefined): DeviceSignals | null {
  return decodeSignals(headerValue(headers, SIGNALS_HEADER));
}

/** SHA-256 (base64url) of an id, for storage: the raw device id never sits in the database. */
export function hashSignalId(id: string): string {
  return createHash("sha256").update(id, "utf8").digest("base64url");
}

/**
 * What the server keeps on a session (and its refresh token) to recognise the device later.
 * Store it as it is; it holds no raw id.
 */
export interface SignalBinding {
  deviceIdHash: string;
  fingerprint: string;
  device: DeviceInfo;
  /** Tab id at login, hashed; informational (a refresh may come from another tab of the same browser). */
  tabIdHash: string;
}

export function bindSignals(signals: DeviceSignals): SignalBinding {
  return {
    deviceIdHash: hashSignalId(signals.deviceId),
    fingerprint: signals.fingerprint,
    device: { ...signals.device },
    tabIdHash: hashSignalId(signals.tabId),
  };
}

/**
 * - `same`: same device id and fingerprint.
 * - `changed`: same device id, but the fingerprint, OS, browser or form factor changed (log it; a browser
 *   update, new screen or language change does this).
 * - `other-device`: a different device id (reject: the token was copied to another browser).
 * - `missing`: the request has no valid signals but the session has a binding.
 * - `unbound`: the session has no binding (created before signals existed, or by a non-browser client).
 */
export type SignalVerdict = "same" | "changed" | "other-device" | "missing" | "unbound";

export interface SignalCheck {
  verdict: SignalVerdict;
  /** What differs: "deviceId", "fingerprint", "os", "browser", "mobile", "timezone", "language", "screen". */
  changes: string[];
  /** True for "same" and "changed"; false otherwise. A caller decides what to do with "missing"/"unbound". */
  sameDevice: boolean;
}

const eq = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/** Compares a stored binding with a request's signals. Pure; never throws. */
export function checkSignals(binding: SignalBinding | null | undefined, incoming: DeviceSignals | null | undefined): SignalCheck {
  if (!binding) return { verdict: "unbound", changes: [], sameDevice: false };
  if (!incoming) return { verdict: "missing", changes: [], sameDevice: false };
  if (!eq(binding.deviceIdHash, hashSignalId(incoming.deviceId))) return { verdict: "other-device", changes: ["deviceId"], sameDevice: false };
  const changes: string[] = [];
  if (binding.fingerprint !== incoming.fingerprint) changes.push("fingerprint");
  for (const k of ["os", "browser", "mobile", "timezone", "language", "screen"] as const) {
    if (binding.device?.[k] !== incoming.device[k]) changes.push(k);
  }
  return { verdict: changes.length ? "changed" : "same", changes, sameDevice: true };
}

export interface SignalPolicy {
  /** Reject a session used with another device id. Default true. */
  rejectOtherDevice?: boolean;
  /** Reject when signals are missing but the session is bound. Default false (old clients keep working). */
  requireSignals?: boolean;
}

/**
 * Applies a policy to a check: `allow` false means end the session; `log` true means write an audit
 * entry (every verdict except "same" and "unbound").
 */
export function decide(check: SignalCheck, policy: SignalPolicy = {}): { allow: boolean; log: boolean } {
  const rejectOther = policy.rejectOtherDevice ?? true;
  switch (check.verdict) {
    case "same":
    case "unbound":
      return { allow: true, log: false };
    case "changed":
      return { allow: true, log: true };
    case "other-device":
      return { allow: !rejectOther, log: true };
    case "missing":
      return { allow: !policy.requireSignals, log: true };
  }
}
