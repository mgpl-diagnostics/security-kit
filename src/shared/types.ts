/** Coarse facts about the device and browser. No canvas, audio, WebGL or font probing. */
export interface DeviceInfo {
  /** "Windows" | "macOS" | "iOS" | "Android" | "ChromeOS" | "Linux" | "Other" */
  os: string;
  /** "Chrome" | "Edge" | "Firefox" | "Safari" | "Opera" | "Samsung Internet" | "Other" */
  browser: string;
  /** Major version only, e.g. "131"; "" when unknown. */
  browserVersion: string;
  mobile: boolean;
  /** BCP 47 language tag, e.g. "en-IN". */
  language: string;
  /** IANA time zone, e.g. "Asia/Kolkata". */
  timezone: string;
  /** "1920x1080" (larger side first, so rotating a phone does not change it); "" when unknown. */
  screen: string;
}

/**
 * The security signals a client sends with login and refresh (and may send with every request).
 * Collected by `@mgpl-diagnostics/security-kit/browser`, read by `@mgpl-diagnostics/security-kit/server`.
 */
export interface DeviceSignals {
  /** Signal format version. */
  v: 1;
  /** Random id kept in the browser's persistent storage: one per browser profile. */
  deviceId: string;
  /** Random id kept in session storage: one per tab. */
  tabId: string;
  /** SHA-256 (hex, 32 chars) of the coarse device attributes; changes when the device's setup changes. */
  fingerprint: string;
  device: DeviceInfo;
  /** The app's own version, when it sets one. */
  app?: string;
}
