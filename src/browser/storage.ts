/** Where the collector keeps its ids. Sync or async, so React Native's AsyncStorage fits too. */
export interface SignalStorage {
  get(key: string): string | null | undefined | Promise<string | null | undefined>;
  set(key: string, value: string): void | Promise<void>;
  remove?(key: string): void | Promise<void>;
}

/** In-memory storage: ids last as long as the page (or process). */
export function memoryStorage(): SignalStorage {
  const map = new Map<string, string>();
  return { get: (k) => map.get(k), set: (k, v) => void map.set(k, v), remove: (k) => void map.delete(k) };
}

/**
 * Wraps `localStorage` or `sessionStorage`. Falls back to memory when the storage is missing or throws
 * (private mode, blocked site data, server rendering).
 */
export function webStorage(kind: "local" | "session"): SignalStorage {
  const fallback = memoryStorage();
  const store = (): Storage | null => {
    try {
      const s = (globalThis as Record<string, unknown>)[kind === "local" ? "localStorage" : "sessionStorage"] as Storage | undefined;
      return s ?? null;
    } catch {
      return null;
    }
  };
  return {
    get(k) {
      try {
        const v = store()?.getItem(k);
        if (v != null) return v;
      } catch {
        /* blocked */
      }
      return fallback.get(k);
    },
    set(k, v) {
      fallback.set(k, v);
      try {
        store()?.setItem(k, v);
      } catch {
        /* quota or blocked: memory keeps it */
      }
    },
    remove(k) {
      fallback.remove?.(k);
      try {
        store()?.removeItem(k);
      } catch {
        /* blocked */
      }
    },
  };
}
