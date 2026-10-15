// "@mgpl-diagnostics/security-kit/react": one optional hook. React is an optional peer dependency;
// every other framework uses the collector's subscribe/getSnapshot or signalStore() directly.
import { useEffect, useSyncExternalStore } from "react";
import type { SignalCollector } from "./browser/collect";
import type { DeviceSignals } from "./shared/types";

/**
 * The collector's current signals (null until collected, and during server rendering). Starts
 * collection on mount. Pass a collector created once at module level.
 */
export function useDeviceSignals(collector: SignalCollector): DeviceSignals | null {
  const signals = useSyncExternalStore(collector.subscribe, collector.getSnapshot, () => null);
  useEffect(() => {
    if (!collector.getSnapshot()) collector.collect().catch(() => undefined);
  }, [collector]);
  return signals;
}
