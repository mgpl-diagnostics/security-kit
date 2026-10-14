import { isIP } from "node:net";
import { headerValue, type HeaderSource } from "./signals";

/** "::ffff:10.0.0.1" → "10.0.0.1"; strips brackets and a port; null when it is not an IP address. */
export function normalizeIp(value: string | undefined | null): string | null {
  if (!value) return null;
  let v = value.trim();
  if (v.startsWith("[")) v = v.slice(1, v.indexOf("]") > 0 ? v.indexOf("]") : undefined); // "[::1]:443"
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(v)) v = v.slice(0, v.lastIndexOf(":")); // "1.2.3.4:5678"
  if (/^::ffff:\d{1,3}(\.\d{1,3}){3}$/i.test(v)) v = v.slice(7);
  return isIP(v) ? v.toLowerCase() : null;
}

export interface ClientIpOptions {
  /** The socket's peer address (Fastify `request.socket.remoteAddress`, Node `req.socket.remoteAddress`). */
  remoteAddress?: string | null;
  headers?: HeaderSource;
  /**
   * How many reverse proxies in front of the server append to X-Forwarded-For (a load balancer = 1,
   * CDN + load balancer = 2). Default 0: the header is ignored, because any client can send it.
   */
  trustedHops?: number;
}

/**
 * The client's IP address. With `trustedHops` = n, walks X-Forwarded-For from the right and takes the
 * address the outermost trusted proxy saw, so a spoofed left-hand entry is never used.
 */
export function clientIp(o: ClientIpOptions): string | null {
  const peer = normalizeIp(o.remoteAddress);
  const hops = Math.max(0, Math.floor(o.trustedHops ?? 0));
  if (hops === 0) return peer;
  const xff = headerValue(o.headers, "x-forwarded-for");
  const chain = (xff ? xff.split(",").map((s) => s.trim()).filter(Boolean) : []).concat(peer ? [peer] : []);
  // chain = [client?, …, proxy1, peer]; the trusted part is the last `hops` entries
  const idx = chain.length - 1 - hops;
  return idx >= 0 ? normalizeIp(chain[idx]) : normalizeIp(chain[0]);
}
