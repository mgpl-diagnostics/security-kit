// Thin adapters that attach the signals header in any HTTP or GraphQL client. None imports a library:
// each matches the library's hook shape, so security-kit keeps zero dependencies.
import { SIGNALS_HEADER } from "../shared/constants";
import type { SignalCollector } from "./collect";

/** What to do when signals can't be collected (no Web Crypto, storage error): by default, send without. */
export interface AdapterOptions {
  onError?: (error: unknown) => void;
}

async function value(collector: SignalCollector, o: AdapterOptions): Promise<string | null> {
  try {
    return await collector.headerValue();
  } catch (e) {
    o.onError?.(e);
    return null;
  }
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * A `fetch` that adds the signals header. Pass it wherever a library takes a custom fetch:
 * `@mgpl-diagnostics/client` (`fetch`), graphql-request, urql (`fetch`), Apollo's HttpLink (`fetch`),
 * ofetch, wretch, TanStack Query / SWR query functions, or plain code.
 * A header already set by the caller is kept.
 */
export function signalFetch(collector: SignalCollector, fetchImpl?: FetchLike, o: AdapterOptions = {}): FetchLike {
  return async (input, init) => {
    const base = fetchImpl ?? ((i: RequestInfo | URL, n?: RequestInit) => fetch(i, n));
    const headers = new Headers(init?.headers ?? (typeof Request !== "undefined" && input instanceof Request ? input.headers : undefined));
    if (!headers.has(SIGNALS_HEADER)) {
      const v = await value(collector, o);
      if (v) headers.set(SIGNALS_HEADER, v);
    }
    return base(input, { ...init, headers });
  };
}

/**
 * Returns `headers` plus the signals header, as a plain object. For anything that takes a headers
 * object or a headers function: `@mgpl-diagnostics/client` (`headers: () => mergeSignalHeaders(signals)`),
 * graphql-request's `requestMiddleware`, graphql-ws `connectionParams`, socket.io `extraHeaders`, Angular
 * HttpClient interceptors.
 */
export async function mergeSignalHeaders(collector: SignalCollector, headers?: HeadersInit, o: AdapterOptions = {}): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  new Headers(headers).forEach((v, k) => (out[k] = v));
  if (!(SIGNALS_HEADER in out)) {
    const v = await value(collector, o);
    if (v) out[SIGNALS_HEADER] = v;
  }
  return out;
}

interface AxiosLikeConfig {
  headers?: { set?(name: string, value: string): unknown; has?(name: string): boolean } & Record<string, unknown>;
}

/** An axios request interceptor: `axios.interceptors.request.use(axiosSignals(signals))`. */
export function axiosSignals<C extends AxiosLikeConfig>(collector: SignalCollector, o: AdapterOptions = {}): (config: C) => Promise<C> {
  return async (config) => {
    const v = await value(collector, o);
    if (!v) return config;
    const h = config.headers;
    if (h && typeof h.set === "function") {
      if (!h.has?.(SIGNALS_HEADER)) h.set(SIGNALS_HEADER, v);
    } else {
      config.headers = { ...(h ?? {}), [SIGNALS_HEADER]: (h?.[SIGNALS_HEADER] as string | undefined) ?? v };
    }
    return config;
  };
}

/** A ky `beforeRequest` hook: `ky.create({ hooks: { beforeRequest: [kySignals(signals)] } })`. */
export function kySignals(collector: SignalCollector, o: AdapterOptions = {}): (request: Request) => Promise<void> {
  return async (request) => {
    if (request.headers.has(SIGNALS_HEADER)) return;
    const v = await value(collector, o);
    if (v) request.headers.set(SIGNALS_HEADER, v);
  };
}

/**
 * An Apollo Client context setter: `setContext(apolloSignals(signals))` from `@apollo/client/link/context`.
 * Also fits any library whose hook receives and returns `{ headers }`.
 */
export function apolloSignals(collector: SignalCollector, o: AdapterOptions = {}) {
  return async (_operation: unknown, prev: { headers?: Record<string, string> } = {}) => ({
    headers: { ...(prev.headers ?? {}), ...(await mergeSignalHeaders(collector, prev.headers, o)) },
  });
}

/**
 * A readable store (the Svelte store contract: `subscribe` calls the listener at once, then on every
 * change). Use it as `$signals` in Svelte, or wrap it in one line for Vue (`shallowRef` + `subscribe`),
 * Solid (`from`), Angular (`toSignal` via an Observable) or RxJS. Starts collection on first subscribe.
 */
export function signalStore(collector: SignalCollector, o: AdapterOptions = {}) {
  return {
    subscribe(listener: (signals: ReturnType<SignalCollector["getSnapshot"]>) => void): () => void {
      listener(collector.getSnapshot());
      const off = collector.subscribe(listener);
      if (!collector.getSnapshot()) collector.collect().catch((e) => o.onError?.(e));
      return off;
    },
  };
}
