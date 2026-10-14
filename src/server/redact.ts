/** Keys (compared without case, "-" or "_") whose values are always hidden. */
export const SENSITIVE_KEYS = [
  "password", "newpassword", "currentpassword", "oldpassword", "passwordhash",
  "token", "accesstoken", "refreshtoken", "idtoken", "resettoken", "sessiontoken",
  "authorization", "proxyauthorization", "cookie", "setcookie",
  "secret", "clientsecret", "jwtsecret", "apikey", "xapikey", "privatekey",
  "otp", "pin", "cvv", "cardnumber",
] as const;

const SUFFIXES = ["password", "token", "secret", "apikey"];
export const REDACTED = "[redacted]";

const norm = (k: string) => k.toLowerCase().replace(/[-_]/g, "");

export interface RedactOptions {
  /** More keys to hide (any form: "x-api-key", "myField"). */
  keys?: readonly string[];
  /** Maximum depth; deeper values become "[depth]". Default 8. */
  maxDepth?: number;
}

/**
 * A copy of `value` with secrets replaced by "[redacted]", for logs and error reports. Handles nested
 * objects, arrays, Headers-like maps and cycles. Strings that look like bearer tokens are hidden too.
 */
export function redact<T>(value: T, o: RedactOptions = {}): T {
  const extra = new Set((o.keys ?? []).map(norm));
  const exact = new Set<string>([...SENSITIVE_KEYS, ...extra]);
  const maxDepth = o.maxDepth ?? 8;
  const seen = new WeakSet<object>();
  const sensitive = (k: string) => {
    const n = norm(k);
    return exact.has(n) || SUFFIXES.some((s) => n.endsWith(s));
  };

  const walk = (v: unknown, depth: number): unknown => {
    if (typeof v === "string") return /^Bearer\s+\S+/i.test(v) ? "Bearer [redacted]" : v;
    if (v === null || typeof v !== "object") return v;
    if (v instanceof Date) return v;
    if (seen.has(v)) return "[circular]";
    if (depth >= maxDepth) return "[depth]";
    seen.add(v);
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, sensitive(String(k)) ? REDACTED : walk(x, depth + 1)]));
    if (typeof (v as { forEach?: unknown }).forEach === "function" && typeof (v as { get?: unknown }).get === "function") {
      // Fetch Headers
      const out: Record<string, unknown> = {};
      (v as Headers).forEach((x, k) => (out[k] = sensitive(k) ? REDACTED : walk(x, depth + 1)));
      return out;
    }
    if (v instanceof Error) return { name: v.name, message: walk(v.message, depth + 1) };
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = sensitive(k) ? REDACTED : walk(x, depth + 1);
    return out;
  };
  return walk(value, 0) as T;
}

/** "kavita.sharma@example.com" → "k***a@example.com". Returns "" for anything that is not an email. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1) return "";
  const user = email.slice(0, at);
  const shown = user.length <= 2 ? `${user[0]}*` : `${user[0]}***${user[user.length - 1]}`;
  return `${shown}${email.slice(at)}`;
}

/** Keeps the last `visible` digits: "+91 98765 43210" → "******3210". */
export function maskPhone(phone: string, visible = 4): string {
  const digits = phone.replace(/\D/g, "");
  if (!digits) return "";
  const keep = Math.min(visible, Math.max(0, digits.length - 4));
  return "*".repeat(digits.length - keep).slice(-6) + digits.slice(digits.length - keep);
}
