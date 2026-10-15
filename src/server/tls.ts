// TLS client fingerprint (JA4 / JA3). It comes from the TLS ClientHello, so no browser code can collect
// it: the server that terminates TLS computes it. Behind a reverse proxy, that proxy (nginx with a JA4
// module, Envoy, CloudFront, Cloudflare) passes it on in a request header, which is read here with the
// same trust model as X-Forwarded-For: only when the request came through a trusted proxy.
import { headerValue, type HeaderSource } from "./signals";

export type TlsFingerprintKind = "ja4" | "ja3" | "other";

export interface TlsFingerprint {
  /** "ja4" (e.g. t13d1516h2_8daaf6152771_e5627efa2ab1), "ja3" (32-hex MD5), or another proxy-specific form. */
  kind: TlsFingerprintKind;
  /** The fingerprint as the proxy sent it (JA4 / JA3 lower-cased). Not secret, but store a hash (see auth-kit). */
  value: string;
}

export interface TlsFingerprintOptions {
  headers?: HeaderSource;
  /**
   * The header the TLS-terminating proxy sets, e.g. "x-ja4". Unset (the default): no fingerprint.
   * The proxy must SET it (overwrite), never pass a client's value through.
   */
  header?: string | null;
  /** Reverse proxies in front of the server (as for clientIp). 0 (default): the header is ignored, because any client can send it. */
  trustedHops?: number;
}

const JA4 = /^[tqd][0-9a-z]{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/;
const JA3 = /^[0-9a-f]{32}$/;
const OTHER = /^[A-Za-z0-9_.:,+\/=-]{8,256}$/;

/** Classifies and normalises one header value; null when it is malformed or oversized. Never throws. */
export function parseTlsFingerprint(raw: string | null | undefined): TlsFingerprint | null {
  if (typeof raw !== "string" || raw.length > 256) return null;
  const v = raw.trim();
  const lower = v.toLowerCase();
  if (JA4.test(lower)) return { kind: "ja4", value: lower };
  if (JA3.test(lower)) return { kind: "ja3", value: lower };
  return OTHER.test(v) ? { kind: "other", value: v } : null;
}

/**
 * The request's TLS fingerprint from the proxy header, or null: no header configured, no trusted proxy
 * (`trustedHops` 0), header missing (TLS terminated somewhere that does not compute it), or malformed.
 * Never throws; a missing fingerprint is never an error.
 */
export function readTlsFingerprint(o: TlsFingerprintOptions): TlsFingerprint | null {
  if (!o.header || Math.floor(o.trustedHops ?? 0) < 1) return null;
  return parseTlsFingerprint(headerValue(o.headers, o.header));
}
