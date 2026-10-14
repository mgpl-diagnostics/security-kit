import type { DeviceInfo } from "../shared/types";

/**
 * The parts of the browser environment the collector reads. Defaults to `globalThis`; tests and
 * non-browser apps (React Native, Electron main) pass their own.
 */
export interface SignalEnvironment {
  navigator?: {
    userAgent?: string;
    language?: string;
    platform?: string;
    hardwareConcurrency?: number;
    deviceMemory?: number;
    maxTouchPoints?: number;
    userAgentData?: { mobile?: boolean; platform?: string };
  };
  screen?: { width?: number; height?: number; colorDepth?: number };
  /** IANA time zone; defaults to Intl. */
  timezone?: string;
}

export function defaultEnvironment(): SignalEnvironment {
  const g = globalThis as unknown as { navigator?: SignalEnvironment["navigator"]; screen?: SignalEnvironment["screen"] };
  let timezone = "";
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";
  } catch {
    /* no Intl time zones */
  }
  return { navigator: g.navigator, screen: g.screen, timezone };
}

const cut = (s: string) => s.slice(0, 64);

function osOf(ua: string, touchPoints: number, hint?: string): string {
  if (/Windows/i.test(ua) || hint === "Windows") return "Windows";
  if (/Android/i.test(ua) || hint === "Android") return "Android";
  if (/iPhone|iPad|iPod/i.test(ua) || hint === "iOS") return "iOS";
  if (/CrOS/i.test(ua) || hint === "Chrome OS" || hint === "ChromeOS") return "ChromeOS";
  // iPadOS 13+ reports itself as a Mac; a Mac has no touch screen
  if (/Macintosh|Mac OS X/i.test(ua) || hint === "macOS") return touchPoints > 1 ? "iOS" : "macOS";
  if (/Linux/i.test(ua) || hint === "Linux") return "Linux";
  return "Other";
}

const BROWSERS: [RegExp, string][] = [
  [/Edg(?:e|A|iOS)?\/(\d+)/, "Edge"],
  [/(?:OPR|Opera)\/(\d+)/, "Opera"],
  [/SamsungBrowser\/(\d+)/, "Samsung Internet"],
  [/(?:Firefox|FxiOS)\/(\d+)/, "Firefox"],
  [/(?:Chrome|CriOS)\/(\d+)/, "Chrome"],
  [/Version\/(\d+)[^ ]* (?:Mobile\/\S+ )?Safari\//, "Safari"],
];

/** Browser family and major version from a user-agent string. */
export function browserOf(ua: string): { browser: string; browserVersion: string } {
  for (const [re, name] of BROWSERS) {
    const m = re.exec(ua);
    if (m) return { browser: name, browserVersion: m[1] ?? "" };
  }
  return { browser: "Other", browserVersion: "" };
}

/** Coarse `DeviceInfo` from the environment. Never throws; unknown values are "". */
export function deviceInfo(env: SignalEnvironment = defaultEnvironment()): DeviceInfo {
  const nav = env.navigator ?? {};
  const ua = typeof nav.userAgent === "string" ? nav.userAgent : "";
  const touch = typeof nav.maxTouchPoints === "number" ? nav.maxTouchPoints : 0;
  const os = osOf(ua, touch, nav.userAgentData?.platform);
  const { browser, browserVersion } = browserOf(ua);
  const mobile = typeof nav.userAgentData?.mobile === "boolean" ? nav.userAgentData.mobile : /Mobi|iPhone|iPod|Android.*Mobile/i.test(ua);
  const w = Math.round(env.screen?.width ?? 0), h = Math.round(env.screen?.height ?? 0);
  return {
    os,
    browser,
    browserVersion: cut(browserVersion),
    mobile,
    language: cut(typeof nav.language === "string" ? nav.language : ""),
    timezone: cut(env.timezone ?? ""),
    screen: w > 0 && h > 0 ? `${Math.max(w, h)}x${Math.min(w, h)}` : "",
  };
}

/**
 * The attributes the fingerprint hashes. Deliberately coarse and stable: no browser version (it changes
 * with every update), no canvas, audio, WebGL or font probing.
 */
export function fingerprintComponents(env: SignalEnvironment = defaultEnvironment()): Record<string, string | number | boolean> {
  const info = deviceInfo(env);
  const nav = env.navigator ?? {};
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  return {
    os: info.os,
    browser: info.browser,
    mobile: info.mobile,
    platform: typeof nav.platform === "string" ? nav.platform.slice(0, 64) : "",
    language: info.language,
    timezone: info.timezone,
    screen: info.screen,
    colorDepth: num(env.screen?.colorDepth),
    cores: num(nav.hardwareConcurrency),
    memory: num(nav.deviceMemory),
    touch: num(nav.maxTouchPoints),
  };
}
