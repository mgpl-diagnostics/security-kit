// Thin server adapters. None imports a framework: each matches its hook shape structurally.
//   any framework / GraphQL context → requestSecurity()
//   Fetch-standard (Hono, Next.js route handlers, Bun, Deno, GraphQL Yoga, workers) → fetchSecurity()
//   Express / Connect / node:http → expressSecurity()
//   Fastify → app.register(fastifySecurity())
import type { DeviceSignals } from "../shared/types";
import { corsPolicy, securityHeaders, type CorsOptions, type SecurityHeaderOptions } from "./headers";
import { clientIp } from "./ip";
import { headerValue, readSignals, type HeaderSource } from "./signals";
import { readTlsFingerprint, type TlsFingerprint } from "./tls";

export interface RequestSecurity {
  /** Client IP (see clientIp and `trustedHops`). */
  ip: string | null;
  /** Validated device signals, or null. */
  signals: DeviceSignals | null;
  userAgent: string | null;
  origin: string | null;
  /** TLS client fingerprint from the trusted proxy's header (see readTlsFingerprint), or null. */
  tlsFingerprint: TlsFingerprint | null;
}

export interface SecurityOptions {
  /** Response security headers; false to leave them to someone else. Default securityHeaders(). */
  headers?: SecurityHeaderOptions | false;
  /** CORS; omit or false to leave CORS to someone else. */
  cors?: CorsOptions | false;
  /** Reverse proxies that append to X-Forwarded-For. Default 0. */
  trustedHops?: number;
  /** Header the TLS-terminating proxy puts the JA4/JA3 fingerprint in (e.g. "x-ja4"). Read only when trustedHops ≥ 1. */
  tlsFingerprintHeader?: string;
}

/** IP, signals, user agent and origin of any request. Use it to build a GraphQL context. */
export function requestSecurity(input: { headers?: HeaderSource; remoteAddress?: string | null; trustedHops?: number; tlsFingerprintHeader?: string }): RequestSecurity {
  return {
    ip: clientIp(input),
    signals: readSignals(input.headers),
    userAgent: headerValue(input.headers, "user-agent")?.slice(0, 512) ?? null,
    origin: headerValue(input.headers, "origin") ?? null,
    tlsFingerprint: readTlsFingerprint({ headers: input.headers, header: input.tlsFingerprintHeader, trustedHops: input.trustedHops }),
  };
}

function prepare(o: SecurityOptions) {
  const base = o.headers === false ? {} : securityHeaders(o.headers ?? {});
  const cors = o.cors ? corsPolicy(o.cors) : null;
  return {
    /** Response headers for this request. */
    headers(origin: string | null | undefined, preflight: boolean): Record<string, string> {
      return { ...base, ...(cors ? cors.headers(origin, preflight) : {}) };
    },
    /** A CORS preflight this adapter answers itself (only when CORS is configured). */
    isPreflight(method: string | undefined, headers: HeaderSource | undefined): boolean {
      return !!cors && method?.toUpperCase() === "OPTIONS" && !!headerValue(headers, "access-control-request-method");
    },
  };
}

/**
 * For Fetch-standard servers. `handle(request, remoteAddress)` returns the request's security info,
 * the headers to add to the response, and a ready 204 `preflight` response for CORS preflights.
 *
 *   const sec = fetchSecurity({ cors: { origins } });
 *   const { security, headers, preflight } = sec.handle(request, ip);
 *   if (preflight) return preflight;
 */
export function fetchSecurity(o: SecurityOptions = {}) {
  const p = prepare(o);
  return {
    handle(request: Request, remoteAddress?: string | null) {
      const security = requestSecurity({ headers: request.headers, remoteAddress, trustedHops: o.trustedHops, tlsFingerprintHeader: o.tlsFingerprintHeader });
      const pre = p.isPreflight(request.method, request.headers);
      const headers = p.headers(security.origin, pre);
      return { security, headers, preflight: pre ? new Response(null, { status: 204, headers }) : null };
    },
    /** Copies the headers onto a response (returns a new Response when the original's are immutable). */
    apply(response: Response, headers: Record<string, string>): Response {
      try {
        for (const [k, v] of Object.entries(headers)) response.headers.set(k, v);
        return response;
      } catch {
        const copy = new Response(response.body, response);
        for (const [k, v] of Object.entries(headers)) copy.headers.set(k, v);
        return copy;
      }
    },
  };
}

interface NodeLikeRequest {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string | null };
  security?: RequestSecurity;
}
interface NodeLikeResponse {
  setHeader(name: string, value: string): unknown;
  statusCode: number;
  end(): unknown;
}

/**
 * Express / Connect / node:http middleware: sets the headers, answers CORS preflights with 204, and puts
 * the security info on `req.security`. `app.use(expressSecurity({ cors: { origins }, trustedHops: 1 }))`.
 */
export function expressSecurity(o: SecurityOptions = {}) {
  const p = prepare(o);
  return (req: NodeLikeRequest, res: NodeLikeResponse, next: (err?: unknown) => void) => {
    const security = requestSecurity({ headers: req.headers, remoteAddress: req.socket?.remoteAddress, trustedHops: o.trustedHops, tlsFingerprintHeader: o.tlsFingerprintHeader });
    req.security = security;
    const pre = p.isPreflight(req.method, req.headers);
    for (const [k, v] of Object.entries(p.headers(security.origin, pre))) res.setHeader(k, v);
    if (pre) {
      res.statusCode = 204;
      res.end();
      return;
    }
    next();
  };
}

interface FastifyLikeInstance {
  decorateRequest(name: string, value: unknown): unknown;
  addHook(name: "onRequest", hook: (request: FastifyLikeRequest, reply: FastifyLikeReply) => Promise<unknown>): unknown;
}
interface FastifyLikeRequest {
  method: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string | null };
  raw?: { socket?: { remoteAddress?: string | null } };
  security?: RequestSecurity | null;
}
interface FastifyLikeReply {
  header(name: string, value: string): unknown;
  code(status: number): FastifyLikeReply;
  send(payload?: unknown): unknown;
}

/**
 * A Fastify plugin (applies to the whole app, like fastify-plugin): sets the headers, answers CORS
 * preflights, and decorates `request.security`. `await app.register(fastifySecurity({ trustedHops: 1 }))`.
 * Leave `cors` unset when @fastify/cors already handles CORS.
 */
export function fastifySecurity(o: SecurityOptions = {}) {
  const p = prepare(o);
  const plugin = (app: FastifyLikeInstance, _opts: unknown, done: (err?: Error) => void) => {
    app.decorateRequest("security", null);
    app.addHook("onRequest", async (request, reply) => {
      const remoteAddress = request.socket?.remoteAddress ?? request.raw?.socket?.remoteAddress;
      const security = requestSecurity({ headers: request.headers, remoteAddress, trustedHops: o.trustedHops, tlsFingerprintHeader: o.tlsFingerprintHeader });
      request.security = security;
      const pre = p.isPreflight(request.method, request.headers);
      for (const [k, v] of Object.entries(p.headers(security.origin, pre))) reply.header(k, v);
      if (pre) return reply.code(204).send();
      return undefined;
    });
    done();
  };
  // what fastify-plugin sets, so hooks and the decorator apply outside the plugin's own scope
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for("skip-override")] = true;
  (plugin as unknown as Record<symbol, unknown>)[Symbol.for("fastify.display-name")] = "mgpl-security";
  return plugin;
}
