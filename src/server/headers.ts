import { SIGNALS_HEADER } from "../shared/constants";

export interface SecurityHeaderOptions {
  /** HSTS max-age in seconds; false to omit (plain-HTTP development). Default one year. */
  hsts?: number | false;
  /**
   * Content-Security-Policy. Default for a JSON / GraphQL API: nothing may load and nothing may frame it.
   * Pass a string for pages (GraphiQL needs its own), or false to omit.
   */
  csp?: string | false;
  /** Cache-Control: no-store. Default true (responses carry personal data and tokens). */
  noStore?: boolean;
}

export const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/** Response headers for the API. Set them on every response (a Fastify onSend hook, for example). */
export function securityHeaders(o: SecurityHeaderOptions = {}): Record<string, string> {
  const h: Record<string, string> = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "x-dns-prefetch-control": "off",
  };
  const hsts = o.hsts ?? 31_536_000;
  if (hsts !== false) h["strict-transport-security"] = `max-age=${Math.max(0, Math.floor(hsts))}; includeSubDomains`;
  const csp = o.csp ?? API_CSP;
  if (csp !== false) h["content-security-policy"] = csp;
  if (o.noStore ?? true) h["cache-control"] = "no-store";
  return h;
}

export interface CorsOptions {
  /**
   * Allowed origins: exact ("https://lab.example.in"), a subdomain pattern ("https://*.example.in", which
   * does not match the bare domain), or "*" (any origin, and then never credentials).
   */
  origins: readonly string[];
  /** Extra request headers to allow (authorization, content-type and x-mgpl-signals are always allowed). */
  allowHeaders?: readonly string[];
  methods?: readonly string[];
  /** Access-Control-Allow-Credentials (cookies). Default false: the API uses bearer tokens. */
  credentials?: boolean;
  /** Preflight cache, seconds. Default 600. */
  maxAge?: number;
}

function matches(pattern: string, origin: string): boolean {
  if (pattern === origin) return true;
  const m = /^(https?):\/\/\*\.(.+)$/.exec(pattern);
  if (!m) return false;
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.origin !== origin || `${m[1]}:` !== url.protocol) return false;
  const host = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  return host.endsWith(`.${m[2]}`) && host.length > m[2]!.length + 1;
}

/** A CORS policy: `allowed(origin)` and the response `headers(origin)` (empty when not allowed). */
export function corsPolicy(o: CorsOptions) {
  const any = o.origins.includes("*");
  if (any && o.credentials) throw new Error("security-kit: CORS cannot allow credentials for any origin ('*')");
  const allowHeaders = [...new Set(["authorization", "content-type", SIGNALS_HEADER, ...(o.allowHeaders ?? []).map((h) => h.toLowerCase())])];
  const methods = o.methods ?? ["GET", "POST", "OPTIONS"];

  const allowed = (origin: string | null | undefined): origin is string =>
    typeof origin === "string" && origin !== "null" && (any || o.origins.some((p) => matches(p, origin)));

  return {
    allowed,
    /** Headers for the response; `preflight` adds the Allow-Methods / Allow-Headers / Max-Age set. */
    headers(origin: string | null | undefined, preflight = false): Record<string, string> {
      if (!allowed(origin)) return { vary: "Origin" };
      const h: Record<string, string> = { "access-control-allow-origin": any ? "*" : origin, vary: "Origin" };
      if (o.credentials) h["access-control-allow-credentials"] = "true";
      if (preflight) {
        h["access-control-allow-methods"] = methods.join(", ");
        h["access-control-allow-headers"] = allowHeaders.join(", ");
        h["access-control-max-age"] = String(o.maxAge ?? 600);
      }
      return h;
    },
  };
}
