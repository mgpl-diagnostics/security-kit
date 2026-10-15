import { ID_PATTERN } from "../shared/constants";
import { canonicalJson, randomId, sha256Hex } from "../shared/crypto";
import { encodeSignals, signalHeaders } from "../shared/signals";
import type { DeviceSignals } from "../shared/types";
import { defaultEnvironment, deviceInfo, fingerprintComponents, type SignalEnvironment } from "./device";
import { webStorage, type SignalStorage } from "./storage";

export interface SignalCollectorOptions {
  /** Keeps the device id. Default: localStorage (memory when unavailable). */
  storage?: SignalStorage;
  /** Keeps the tab id. Default: sessionStorage (memory when unavailable). */
  tabStorage?: SignalStorage;
  /** Storage key prefix. Default "mgpl.". */
  prefix?: string;
  /** The app's version, sent as `app`. */
  app?: string;
  /** Where device facts come from. Default: globalThis (navigator, screen, Intl). */
  environment?: () => SignalEnvironment;
}

export interface SignalCollector {
  /** The signals; ids are created on first use and then reused. Cached until `refresh()`. */
  collect(): Promise<DeviceSignals>;
  /** `{ "x-mgpl-signals": "…" }` for a fetch / GraphQL request. */
  headers(): Promise<Record<string, string>>;
  /** The encoded header value alone. */
  headerValue(): Promise<string>;
  /** Re-reads the device facts (after a resize or a language change, for example). */
  refresh(): Promise<DeviceSignals>;
  /** Forgets the device and tab ids (for "forget this device" or after a sign-out on a shared PC). */
  reset(): Promise<void>;
  /**
   * The last collected signals, or null before the first `collect()`. The same object until the
   * signals change, so it works as a snapshot for React's useSyncExternalStore and similar.
   */
  getSnapshot(): DeviceSignals | null;
  /**
   * Calls `listener` whenever the signals change (first collect, refresh, reset). Returns the
   * unsubscribe function. Fits any reactive library: React, Vue, Svelte, Solid, Angular signals, RxJS.
   */
  subscribe(listener: (signals: DeviceSignals | null) => void): () => void;
}

/**
 * Collects the security signals the backend checks at login and refresh. Framework-agnostic: call
 * `headers()` from any fetch wrapper, GraphQL client or query library.
 *
 *   const signals = createSignalCollector({ app: "lab-panel@1.4.0" });
 *   fetch(url, { headers: { ...(await signals.headers()), authorization } });
 */
export function createSignalCollector(o: SignalCollectorOptions = {}): SignalCollector {
  const storage = o.storage ?? webStorage("local");
  const tabStorage = o.tabStorage ?? webStorage("session");
  const prefix = o.prefix ?? "mgpl.";
  const env = o.environment ?? defaultEnvironment;
  let cached: Promise<DeviceSignals> | null = null;
  let snapshot: DeviceSignals | null = null;
  let generation = 0;
  const listeners = new Set<(signals: DeviceSignals | null) => void>();
  const publish = (next: DeviceSignals | null) => {
    snapshot = next;
    for (const l of [...listeners]) {
      try {
        l(next);
      } catch {
        /* a listener's error must not break collection */
      }
    }
  };

  async function idFrom(store: SignalStorage, key: string): Promise<string> {
    const existing = await store.get(prefix + key);
    if (typeof existing === "string" && ID_PATTERN.test(existing)) return existing;
    const id = randomId();
    await store.set(prefix + key, id);
    return id;
  }

  async function build(): Promise<DeviceSignals> {
    const e = env();
    const [deviceId, tabId, hash] = await Promise.all([
      idFrom(storage, "deviceId"),
      idFrom(tabStorage, "tabId"),
      sha256Hex(canonicalJson(fingerprintComponents(e))),
    ]);
    return { v: 1, deviceId, tabId, fingerprint: hash.slice(0, 32), device: deviceInfo(e), ...(o.app ? { app: o.app.slice(0, 64) } : {}) };
  }

  const collect = () => {
    if (!cached) {
      const gen = generation;
      cached = build().then(
        (signals) => {
          // a refresh() or reset() during the build makes this result stale
          if (gen === generation && signals !== snapshot) publish(signals);
          return signals;
        },
        (err) => {
          if (gen === generation) cached = null; // retry next time
          throw err;
        },
      );
    }
    return cached;
  };

  return {
    collect,
    headers: async () => signalHeaders(await collect()),
    headerValue: async () => encodeSignals(await collect()),
    refresh() {
      generation++;
      cached = null;
      return collect();
    },
    async reset() {
      generation++;
      cached = null;
      await storage.remove?.(prefix + "deviceId");
      await tabStorage.remove?.(prefix + "tabId");
      publish(null);
    },
    getSnapshot: () => snapshot,
    subscribe(listener) {
      listeners.add(listener);
      return () => void listeners.delete(listener);
    },
  };
}
