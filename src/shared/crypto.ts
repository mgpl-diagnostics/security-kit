// Primitives that run unchanged in browsers, Node.js >= 20, workers and React Native with Web Crypto:
// only globalThis.crypto, TextEncoder, btoa and atob. No Buffer, no node: imports.

const enc = new TextEncoder();
const dec = new TextDecoder();

function webCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.getRandomValues) throw new Error("security-kit: Web Crypto (globalThis.crypto) is not available");
  return c;
}

/** base64url (RFC 4648 §5, no padding) of bytes or of a UTF-8 string. */
export function toBase64Url(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? enc.encode(input) : input;
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Bytes of a base64url string; null when it is not valid base64url. */
export function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export const utf8 = {
  encode: (s: string) => enc.encode(s),
  decode: (b: Uint8Array) => dec.decode(b),
};

/** Cryptographically random bytes. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  webCrypto().getRandomValues(out);
  return out;
}

/** A random id: `bytes` random bytes as base64url (16 bytes → 22 characters, 128 bits). */
export function randomId(bytes = 16): string {
  return toBase64Url(randomBytes(bytes));
}

/** SHA-256 as lowercase hex (async, Web Crypto). */
export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? enc.encode(input) : input;
  const digest = new Uint8Array(await webCrypto().subtle.digest("SHA-256", data as BufferSource));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Compares two strings in time that depends only on their lengths. Use it for hashes and ids
 * of a fixed length; a different length returns false at once.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** JSON with object keys sorted at every level, so equal values always serialise identically. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
