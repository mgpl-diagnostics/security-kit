// "@mgpl-diagnostics/security-kit/server": the backend part (Node.js >= 20).
export {
  bindSignals,
  checkSignals,
  decide,
  hashSignalId,
  headerValue,
  readSignals,
  type HeaderSource,
  type SignalBinding,
  type SignalCheck,
  type SignalPolicy,
  type SignalVerdict,
} from "./signals";
export { clientIp, normalizeIp, type ClientIpOptions } from "./ip";
export { API_CSP, corsPolicy, securityHeaders, type CorsOptions, type SecurityHeaderOptions } from "./headers";
export { maskEmail, maskPhone, REDACTED, redact, SENSITIVE_KEYS, type RedactOptions } from "./redact";
export * from "../index";
