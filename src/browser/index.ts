// "@mgpl-diagnostics/security-kit/browser": collects device signals in any frontend. No Node.js APIs.
export { apolloSignals, axiosSignals, kySignals, mergeSignalHeaders, signalFetch, signalStore, type AdapterOptions } from "./adapters";
export { createSignalCollector, type SignalCollector, type SignalCollectorOptions } from "./collect";
export { browserOf, defaultEnvironment, deviceInfo, fingerprintComponents, type SignalEnvironment } from "./device";
export { memoryStorage, webStorage, type SignalStorage } from "./storage";
export * from "../index";
