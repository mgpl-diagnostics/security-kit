// npm test: every part of security-kit, run on Node.js. The browser part runs against simulated
// environments and storages (it only needs Web Crypto, which Node.js >= 20 has).
import {
  canonicalJson,
  constantTimeEqual,
  decodeSignals,
  encodeSignals,
  fromBase64Url,
  ID_PATTERN,
  parseSignals,
  randomId,
  sha256Hex,
  SIGNALS_HEADER,
  toBase64Url,
  type DeviceSignals,
} from "../src/index";
import { browserOf, createSignalCollector, deviceInfo, memoryStorage, webStorage, type SignalEnvironment, type SignalStorage } from "../src/browser/index";
import {
  bindSignals,
  checkSignals,
  clientIp,
  corsPolicy,
  decide,
  maskEmail,
  maskPhone,
  normalizeIp,
  readSignals,
  redact,
  securityHeaders,
} from "../src/server/index";

let passed = 0;
const failures: string[] = [];
async function check(name: string, fn: () => unknown | Promise<unknown>) {
  try {
    const r = await fn();
    if (r === false) throw new Error("returned false");
    passed++;
  } catch (e) {
    failures.push(`${name}: ${(e as Error).message}`);
  }
}
function eq(a: unknown, b: unknown) {
  const x = JSON.stringify(a), y = JSON.stringify(b);
  if (x !== y) throw new Error(`expected ${y}, got ${x}`);
}
function ok(v: unknown, msg = "expected truthy") {
  if (!v) throw new Error(msg);
}

// ---------- shared ----------

await check("base64url round-trips bytes and UTF-8", () => {
  eq(toBase64Url("hello"), "aGVsbG8");
  const s = "नमस्ते ✓ <>";
  eq(new TextDecoder().decode(fromBase64Url(toBase64Url(s))!), s);
  const bytes = new Uint8Array([0, 255, 62, 63, 251]);
  eq([...fromBase64Url(toBase64Url(bytes))!], [...bytes]);
  ok(!toBase64Url(bytes).includes("+") && !toBase64Url(bytes).includes("/") && !toBase64Url(bytes).includes("="));
});
await check("fromBase64Url rejects invalid input", () => {
  eq(fromBase64Url("a+b/"), null);
  eq(fromBase64Url("abcde"), null);
  eq(fromBase64Url("ab c"), null);
});
await check("randomId: 22 base64url chars, unique, fits ID_PATTERN", () => {
  const ids = new Set(Array.from({ length: 500 }, () => randomId()));
  eq(ids.size, 500);
  for (const id of ids) ok(id.length === 22 && ID_PATTERN.test(id), id);
});
await check("sha256Hex matches the FIPS 180-2 vector", async () => {
  eq(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});
await check("constantTimeEqual", () => {
  ok(constantTimeEqual("abc", "abc"));
  ok(!constantTimeEqual("abc", "abd"));
  ok(!constantTimeEqual("abc", "abcd"));
});
await check("canonicalJson sorts keys at every level and drops undefined", () => {
  eq(canonicalJson({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: undefined } }), '{"a":{"d":[2,{"y":2,"z":1}]},"b":1}');
});

// ---------- browser: device info ----------

const UA = {
  chromeWin: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  edgeWin: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70",
  safariIphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
  safariMac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  chromeIos: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
  samsung: "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
  firefoxLinux: "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
  opera: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
  chromebook: "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  androidTablet: "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
};

const env = (ua: string, extra: Partial<SignalEnvironment["navigator"]> = {}, screen = { width: 1920, height: 1080, colorDepth: 24 }): SignalEnvironment => ({
  navigator: { userAgent: ua, language: "en-IN", platform: "Win32", hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0, ...extra },
  screen,
  timezone: "Asia/Kolkata",
});

await check("browser and version from user agents", () => {
  eq(browserOf(UA.chromeWin), { browser: "Chrome", browserVersion: "131" });
  eq(browserOf(UA.edgeWin), { browser: "Edge", browserVersion: "131" });
  eq(browserOf(UA.safariIphone), { browser: "Safari", browserVersion: "17" });
  eq(browserOf(UA.safariMac), { browser: "Safari", browserVersion: "17" });
  eq(browserOf(UA.chromeIos), { browser: "Chrome", browserVersion: "131" });
  eq(browserOf(UA.samsung), { browser: "Samsung Internet", browserVersion: "26" });
  eq(browserOf(UA.firefoxLinux), { browser: "Firefox", browserVersion: "133" });
  eq(browserOf(UA.opera), { browser: "Opera", browserVersion: "115" });
  eq(browserOf("curl/8.0"), { browser: "Other", browserVersion: "" });
});
await check("OS and form factor", () => {
  eq([deviceInfo(env(UA.chromeWin)).os, deviceInfo(env(UA.chromeWin)).mobile], ["Windows", false]);
  eq([deviceInfo(env(UA.safariIphone)).os, deviceInfo(env(UA.safariIphone)).mobile], ["iOS", true]);
  eq(deviceInfo(env(UA.safariMac)).os, "macOS");
  eq(deviceInfo(env(UA.safariMac, { maxTouchPoints: 5 })).os, "iOS"); // iPadOS reports a Mac UA
  eq([deviceInfo(env(UA.samsung)).os, deviceInfo(env(UA.samsung)).mobile], ["Android", true]);
  eq([deviceInfo(env(UA.androidTablet)).os, deviceInfo(env(UA.androidTablet)).mobile], ["Android", false]);
  eq(deviceInfo(env(UA.firefoxLinux)).os, "Linux");
  eq(deviceInfo(env(UA.chromebook)).os, "ChromeOS");
  eq(deviceInfo(env(UA.chromeWin, { userAgentData: { mobile: true } })).mobile, true);
});
await check("device info: language, time zone, screen (rotation-proof), empty environment", () => {
  const d = deviceInfo(env(UA.chromeWin));
  eq([d.language, d.timezone, d.screen], ["en-IN", "Asia/Kolkata", "1920x1080"]);
  eq(deviceInfo(env(UA.safariIphone, {}, { width: 390, height: 844, colorDepth: 24 })).screen, "844x390");
  eq(deviceInfo(env(UA.safariIphone, {}, { width: 844, height: 390, colorDepth: 24 })).screen, "844x390");
  eq(deviceInfo({}), { os: "Other", browser: "Other", browserVersion: "", mobile: false, language: "", timezone: "", screen: "" });
});

// ---------- browser: collector ----------

function collector(e: SignalEnvironment, storage = memoryStorage(), tabStorage = memoryStorage(), app?: string) {
  return createSignalCollector({ storage, tabStorage, environment: () => e, app });
}

await check("collector: valid signals; ids persist across collectors sharing storage", async () => {
  const storage = memoryStorage();
  const tab = memoryStorage();
  const a = await collector(env(UA.chromeWin), storage, tab).collect();
  const b = await collector(env(UA.chromeWin), storage, tab).collect();
  ok(parseSignals(a), "parseSignals rejected collected signals");
  eq(a, b);
  const otherTab = await collector(env(UA.chromeWin), storage, memoryStorage()).collect();
  eq(otherTab.deviceId, a.deviceId);
  ok(otherTab.tabId !== a.tabId, "new tab gets a new tab id");
  ok(/^[0-9a-f]{32}$/.test(a.fingerprint));
});
await check("collector: fingerprint ignores browser version, changes with setup", async () => {
  const base = await collector(env(UA.chromeWin)).collect();
  const updated = await collector(env(UA.chromeWin.replace("Chrome/131", "Chrome/132"))).collect();
  eq(updated.fingerprint, base.fingerprint);
  const newScreen = await collector(env(UA.chromeWin, {}, { width: 2560, height: 1440, colorDepth: 24 })).collect();
  ok(newScreen.fingerprint !== base.fingerprint);
  const otherBrowser = await collector(env(UA.firefoxLinux)).collect();
  ok(otherBrowser.fingerprint !== base.fingerprint);
});
await check("collector: caches, refresh re-reads, reset forgets ids", async () => {
  let lang = "en-IN";
  const storage = memoryStorage(), tab = memoryStorage();
  const c = createSignalCollector({ storage, tabStorage: tab, environment: () => env(UA.chromeWin, { language: lang }) });
  const first = await c.collect();
  lang = "hi-IN";
  eq((await c.collect()).device.language, "en-IN");
  const r = await c.refresh();
  eq(r.device.language, "hi-IN");
  eq(r.deviceId, first.deviceId);
  await c.reset();
  const after = await c.collect();
  ok(after.deviceId !== first.deviceId && after.tabId !== first.tabId);
});
await check("collector: headers round-trip through decodeSignals; app is sent", async () => {
  const c = collector(env(UA.safariIphone), memoryStorage(), memoryStorage(), "lab-panel@1.4.0");
  const h = await c.headers();
  eq(Object.keys(h), [SIGNALS_HEADER]);
  eq(decodeSignals(h[SIGNALS_HEADER]), await c.collect());
  eq((await c.collect()).app, "lab-panel@1.4.0");
  ok((await c.headerValue()).length < 1024, "header stays small");
});
await check("collector: replaces a tampered stored id", async () => {
  const storage = memoryStorage();
  await storage.set("mgpl.deviceId", "<script>");
  const s = await collector(env(UA.chromeWin), storage).collect();
  ok(ID_PATTERN.test(s.deviceId));
  eq(await storage.get("mgpl.deviceId"), s.deviceId);
});
await check("collector: async storage (React Native style)", async () => {
  const map = new Map<string, string>();
  const asyncStore: SignalStorage = { get: async (k) => map.get(k) ?? null, set: async (k, v) => void map.set(k, v) };
  const a = await createSignalCollector({ storage: asyncStore, tabStorage: memoryStorage(), environment: () => env(UA.samsung) }).collect();
  const b = await createSignalCollector({ storage: asyncStore, tabStorage: memoryStorage(), environment: () => env(UA.samsung) }).collect();
  eq(a.deviceId, b.deviceId);
});
await check("webStorage: works without storage and when storage throws", async () => {
  const g = globalThis as Record<string, unknown>;
  const s = webStorage("local");
  s.set("k", "v"); // no localStorage in Node: memory
  eq(s.get("k"), "v");
  Object.defineProperty(g, "localStorage", { configurable: true, get() { throw new Error("SecurityError"); } });
  try {
    const t = webStorage("local");
    t.set("k", "w");
    eq(t.get("k"), "w");
    const c = await createSignalCollector({ environment: () => env(UA.chromeWin) }).collect();
    ok(parseSignals(c));
  } finally {
    delete g.localStorage;
  }
});
await check("webStorage: uses a real Storage when present", () => {
  const g = globalThis as Record<string, unknown>;
  const data = new Map<string, string>();
  g.sessionStorage = { getItem: (k: string) => data.get(k) ?? null, setItem: (k: string, v: string) => void data.set(k, v), removeItem: (k: string) => void data.delete(k) };
  try {
    const s = webStorage("session");
    s.set("a", "1");
    eq(data.get("a"), "1");
    s.remove?.("a");
    eq(data.has("a"), false);
  } finally {
    delete g.sessionStorage;
  }
});

// ---------- shared: decoding untrusted input ----------

const good: DeviceSignals = {
  v: 1,
  deviceId: "AAAAAAAAAAAAAAAAAAAAAA",
  tabId: "BBBBBBBBBBBBBBBBBBBBBB",
  fingerprint: "0123456789abcdef0123456789abcdef",
  device: { os: "Windows", browser: "Chrome", browserVersion: "131", mobile: false, language: "en-IN", timezone: "Asia/Kolkata", screen: "1920x1080" },
};
const enc = (v: unknown) => toBase64Url(JSON.stringify(v));

await check("decodeSignals accepts good signals and drops unknown keys", () => {
  eq(decodeSignals(encodeSignals(good)), good);
  eq(decodeSignals(enc({ ...good, extra: "x", device: { ...good.device, gpu: "y" } })), good);
});
await check("decodeSignals rejects malformed, oversized and hostile values", () => {
  const bad: unknown[] = [
    { ...good, v: 2 },
    { ...good, deviceId: "short" },
    { ...good, deviceId: "A".repeat(65) },
    { ...good, tabId: "../../etc/passwd!!!!!!!" },
    { ...good, fingerprint: "XYZ" },
    { ...good, fingerprint: "0123456789ABCDEF0123456789ABCDEF" },
    { ...good, device: { ...good.device, os: "<img src=x>" } },
    { ...good, device: { ...good.device, browser: "a\u0000b" } },
    { ...good, device: { ...good.device, language: "x".repeat(65) } },
    { ...good, device: { ...good.device, mobile: "no" } },
    { ...good, device: null },
    { ...good, app: 42 },
    [good],
    "string",
  ];
  for (const b of bad) eq(decodeSignals(enc(b)), null);
  eq(decodeSignals(undefined), null);
  eq(decodeSignals(""), null);
  eq(decodeSignals("not base64!"), null);
  eq(decodeSignals(toBase64Url("{not json")), null);
  eq(decodeSignals("A".repeat(2049)), null);
  const polluted = decodeSignals(toBase64Url(JSON.stringify(good).replace("{", '{"__proto__":{"polluted":true},')));
  eq(polluted, good);
  eq(({} as Record<string, unknown>).polluted, undefined);
});

// ---------- server: reading and checking signals ----------

await check("readSignals from Fetch Headers, Node headers (any case) and arrays", () => {
  const value = encodeSignals(good);
  eq(readSignals(new Headers({ [SIGNALS_HEADER]: value })), good);
  eq(readSignals({ "x-mgpl-signals": value }), good);
  eq(readSignals({ "X-MGPL-Signals": value }), good);
  eq(readSignals({ "x-mgpl-signals": [value, "junk"] }), good);
  eq(readSignals({}), null);
  eq(readSignals(undefined), null);
});
await check("bindSignals stores no raw ids", () => {
  const b = bindSignals(good);
  const json = JSON.stringify(b);
  ok(!json.includes(good.deviceId) && !json.includes(good.tabId), "raw id in binding");
  eq(b.fingerprint, good.fingerprint);
});
await check("checkSignals verdicts", () => {
  const b = bindSignals(good);
  eq(checkSignals(b, good), { verdict: "same", changes: [], sameDevice: true });
  eq(checkSignals(b, { ...good, tabId: "CCCCCCCCCCCCCCCCCCCCCC" }).verdict, "same"); // another tab of the same browser
  eq(checkSignals(b, { ...good, device: { ...good.device, browserVersion: "132" } }).verdict, "same");
  eq(checkSignals(b, { ...good, fingerprint: "f".repeat(32), device: { ...good.device, screen: "2560x1440" } }), {
    verdict: "changed",
    changes: ["fingerprint", "screen"],
    sameDevice: true,
  });
  eq(checkSignals(b, { ...good, deviceId: "ZZZZZZZZZZZZZZZZZZZZZZ" }), { verdict: "other-device", changes: ["deviceId"], sameDevice: false });
  eq(checkSignals(b, null).verdict, "missing");
  eq(checkSignals(null, good).verdict, "unbound");
});
await check("decide applies the policy", () => {
  const b = bindSignals(good);
  eq(decide(checkSignals(b, good)), { allow: true, log: false });
  eq(decide(checkSignals(b, { ...good, fingerprint: "f".repeat(32) })), { allow: true, log: true });
  eq(decide(checkSignals(b, { ...good, deviceId: "ZZZZZZZZZZZZZZZZZZZZZZ" })), { allow: false, log: true });
  eq(decide(checkSignals(b, { ...good, deviceId: "ZZZZZZZZZZZZZZZZZZZZZZ" }), { rejectOtherDevice: false }), { allow: true, log: true });
  eq(decide(checkSignals(b, null)), { allow: true, log: true });
  eq(decide(checkSignals(b, null), { requireSignals: true }), { allow: false, log: true });
  eq(decide(checkSignals(null, null)), { allow: true, log: false });
});

// ---------- server: client IP ----------

await check("normalizeIp", () => {
  eq(normalizeIp("::ffff:10.0.0.7"), "10.0.0.7");
  eq(normalizeIp("203.0.113.9:51234"), "203.0.113.9");
  eq(normalizeIp("[2001:DB8::1]:443"), "2001:db8::1");
  eq(normalizeIp("2001:db8::1"), "2001:db8::1");
  eq(normalizeIp("not-an-ip"), null);
  eq(normalizeIp("1.2.3.4, 5.6.7.8"), null);
  eq(normalizeIp(undefined), null);
});
await check("clientIp ignores X-Forwarded-For unless proxies are trusted", () => {
  eq(clientIp({ remoteAddress: "::ffff:10.0.0.2", headers: { "x-forwarded-for": "1.1.1.1" } }), "10.0.0.2");
});
await check("clientIp with trusted proxies never takes a spoofed left-hand entry", () => {
  // client 203.0.113.9 sends a fake XFF; the load balancer (10.0.0.2) appends the real address
  eq(clientIp({ remoteAddress: "10.0.0.2", headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.9" }, trustedHops: 1 }), "203.0.113.9");
  // CDN → load balancer → server
  eq(clientIp({ remoteAddress: "10.0.0.2", headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.9, 198.51.100.1" }, trustedHops: 2 }), "203.0.113.9");
  eq(clientIp({ remoteAddress: "10.0.0.2", headers: new Headers({ "x-forwarded-for": "203.0.113.9" }), trustedHops: 1 }), "203.0.113.9");
  eq(clientIp({ remoteAddress: "10.0.0.2", trustedHops: 1 }), "10.0.0.2");
  eq(clientIp({ remoteAddress: "10.0.0.2", headers: { "x-forwarded-for": "garbage" }, trustedHops: 1 }), null);
});

// ---------- server: headers ----------

await check("securityHeaders defaults and options", () => {
  const h = securityHeaders();
  eq(h["strict-transport-security"], "max-age=31536000; includeSubDomains");
  eq(h["x-content-type-options"], "nosniff");
  eq(h["cache-control"], "no-store");
  ok(h["content-security-policy"]!.includes("default-src 'none'"));
  const dev = securityHeaders({ hsts: false, csp: false, noStore: false });
  ok(!("strict-transport-security" in dev) && !("content-security-policy" in dev) && !("cache-control" in dev));
});
await check("corsPolicy: exact, subdomain patterns, schemes, null origin", () => {
  const cors = corsPolicy({ origins: ["https://lab.example.in", "https://*.mgpl.example"] });
  ok(cors.allowed("https://lab.example.in"));
  ok(cors.allowed("https://panel.mgpl.example"));
  ok(cors.allowed("https://a.b.mgpl.example"));
  ok(!cors.allowed("https://mgpl.example"), "bare domain");
  ok(!cors.allowed("http://panel.mgpl.example"), "scheme");
  ok(!cors.allowed("https://evilmgpl.example"), "suffix without dot");
  ok(!cors.allowed("https://mgpl.example.evil.com"), "domain as prefix");
  ok(!cors.allowed("https://lab.example.in.evil.com"));
  ok(!cors.allowed("null"));
  ok(!cors.allowed(undefined));
  eq(cors.headers("https://evil.com"), { vary: "Origin" });
  const pre = cors.headers("https://lab.example.in", true);
  eq(pre["access-control-allow-origin"], "https://lab.example.in");
  ok(pre["access-control-allow-headers"]!.includes(SIGNALS_HEADER));
  ok(!("access-control-allow-credentials" in pre));
});
await check("corsPolicy refuses credentials with '*'", () => {
  let threw = false;
  try {
    corsPolicy({ origins: ["*"], credentials: true });
  } catch {
    threw = true;
  }
  ok(threw);
  eq(corsPolicy({ origins: ["*"] }).headers("https://any.site")["access-control-allow-origin"], "*");
});

// ---------- server: redaction ----------

await check("redact hides secrets at any depth and keeps the rest", () => {
  const input = {
    email: "kavita.sharma@example.com",
    password: "hunter2",
    nested: { refresh_token: "r", "X-Api-Key": "k", list: [{ newPassword: "p", ok: 1 }], stripeSecret: "s" },
    headers: { authorization: "Bearer abc", cookie: "sid=1", accept: "*/*" },
    note: "Bearer xyz.abc.def",
    when: new Date(0),
  };
  const out = redact(input);
  eq(out.password, "[redacted]");
  eq(out.nested.refresh_token, "[redacted]");
  eq(out.nested["X-Api-Key"], "[redacted]");
  eq(out.nested.stripeSecret, "[redacted]");
  eq(out.nested.list[0], { newPassword: "[redacted]", ok: 1 });
  eq(out.headers, { authorization: "[redacted]", cookie: "[redacted]", accept: "*/*" });
  eq(out.note, "Bearer [redacted]");
  eq(out.email, "kavita.sharma@example.com");
  ok(out.when instanceof Date);
  eq(input.password, "hunter2"); // the input is untouched
});
await check("redact: cycles, Headers, Map, errors, extra keys, depth", () => {
  const a: Record<string, unknown> = { name: "x" };
  a.self = a;
  eq(redact(a), { name: "x", self: "[circular]" });
  eq(redact(new Headers({ authorization: "Bearer t", "content-type": "application/json" })), { authorization: "[redacted]", "content-type": "application/json" });
  eq(redact(new Map([["token", "t"], ["id", "1"]])), { token: "[redacted]", id: "1" });
  eq(redact({ uhid: "MGPL-1", phone: "9876543210" }, { keys: ["phone"] }), { uhid: "MGPL-1", phone: "[redacted]" });
  eq(redact(new Error("Bearer abc failed")), { name: "Error", message: "Bearer [redacted]" });
  eq(redact({ a: { b: { c: 1 } } }, { maxDepth: 2 }), { a: { b: "[depth]" } });
});
await check("maskEmail and maskPhone", () => {
  eq(maskEmail("kavita.sharma@example.com"), "k***a@example.com");
  eq(maskEmail("ab@example.com"), "a*@example.com");
  eq(maskEmail("nope"), "");
  eq(maskPhone("+91 98765 43210"), "******3210");
  eq(maskPhone("98765 43210"), "******3210");
  eq(maskPhone(""), "");
});

// ---------- browser: subscribe / snapshot and library adapters ----------

await check("collector subscribe/getSnapshot: first collect, refresh, reset, unsubscribe", async () => {
  const c = collector(env(UA.chromeWin));
  const seen: (DeviceSignals | null)[] = [];
  const off = c.subscribe((s) => seen.push(s));
  eq(c.getSnapshot(), null);
  const a = await c.collect();
  ok(c.getSnapshot() === a, "snapshot is the collected object");
  await c.collect();
  eq(seen.length, 1); // cached: no second notification
  const b = await c.refresh();
  ok(c.getSnapshot() === b && seen.length === 2);
  await c.reset();
  eq(c.getSnapshot(), null);
  eq(seen.length, 3);
  off();
  await c.collect();
  eq(seen.length, 3);
});
await check("collector: a refresh during a collect wins", async () => {
  let lang = "en-IN";
  const c = createSignalCollector({ storage: memoryStorage(), tabStorage: memoryStorage(), environment: () => env(UA.chromeWin, { language: lang }) });
  const first = c.collect();
  lang = "hi-IN";
  const second = c.refresh();
  await first;
  eq((await second).device.language, "hi-IN");
  eq(c.getSnapshot()?.device.language, "hi-IN");
});

const sk = await import("../src/browser/index");
const recorded: { url: string; headers: Headers }[] = [];
const fakeFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  recorded.push({ url: String(input instanceof Request ? input.url : input), headers: new Headers(init?.headers) });
  return new Response("{}");
};

await check("signalFetch adds the header, keeps caller headers, never overwrites", async () => {
  const c = collector(env(UA.chromeWin));
  const f = sk.signalFetch(c, fakeFetch);
  await f("https://api.example/graphql", { headers: { authorization: "Bearer t" } });
  const h = recorded.at(-1)!.headers;
  eq(decodeSignals(h.get(SIGNALS_HEADER)), await c.collect());
  eq(h.get("authorization"), "Bearer t");
  await f("https://api.example/graphql", { headers: { [SIGNALS_HEADER]: "mine" } });
  eq(recorded.at(-1)!.headers.get(SIGNALS_HEADER), "mine");
  await f(new Request("https://api.example/x", { headers: { "x-a": "1" } }));
  eq(recorded.at(-1)!.headers.get("x-a"), "1");
});
await check("signalFetch still sends the request when collection fails", async () => {
  const broken = createSignalCollector({ storage: { get: () => { throw new Error("blocked"); }, set: () => undefined }, tabStorage: memoryStorage(), environment: () => env(UA.chromeWin) });
  const errors: unknown[] = [];
  const res = await sk.signalFetch(broken, fakeFetch, { onError: (e) => errors.push(e) })("https://api.example/");
  eq(res.status, 200);
  eq(recorded.at(-1)!.headers.has(SIGNALS_HEADER), false);
  eq(errors.length, 1);
});
await check("mergeSignalHeaders, apolloSignals, kySignals, axiosSignals", async () => {
  const c = collector(env(UA.chromeWin));
  const v = await c.headerValue();
  eq(await sk.mergeSignalHeaders(c, { Authorization: "Bearer t" }), { authorization: "Bearer t", [SIGNALS_HEADER]: v });
  eq((await sk.apolloSignals(c)({}, { headers: { authorization: "Bearer t" } })).headers[SIGNALS_HEADER], v);
  const req = new Request("https://api.example/");
  await sk.kySignals(c)(req);
  eq(req.headers.get(SIGNALS_HEADER), v);
  // axios 1.x passes an AxiosHeaders instance (set/has); older code passes plain objects
  const store = new Map<string, string>();
  const axiosHeaders = Object.assign(Object.create(null), { set: (k: string, x: string) => void store.set(k, x), has: (k: string) => store.has(k) });
  await sk.axiosSignals(c)({ headers: axiosHeaders });
  eq(store.get(SIGNALS_HEADER), v);
  const plain = await sk.axiosSignals(c)({ headers: { accept: "json" } as Record<string, unknown> });
  eq(plain.headers, { accept: "json", [SIGNALS_HEADER]: v });
  eq((await sk.axiosSignals(c)({})).headers, { [SIGNALS_HEADER]: v });
});
await check("signalStore follows the Svelte store contract", async () => {
  const c = collector(env(UA.chromeWin));
  const seen: (DeviceSignals | null)[] = [];
  const off = sk.signalStore(c).subscribe((s) => seen.push(s));
  eq(seen, [null]); // called at once
  await c.collect();
  eq(seen.length, 2);
  ok(seen[1] === c.getSnapshot());
  off();
});
await check("our client SDK's headers option works directly", async () => {
  const c = collector(env(UA.chromeWin));
  // createMgplGraphQLClient({ headers: () => signals.headers() }) awaits a HeadersInit function
  const headersOption: () => Promise<HeadersInit> = () => c.headers();
  eq(new Headers(await headersOption()).has(SIGNALS_HEADER), true);
});
await check("React: useDeviceSignals renders null on the server and needs no provider", async () => {
  const React = await import("react");
  const { renderToString } = await import("react-dom/server");
  const { useDeviceSignals } = await import("../src/react");
  const c = collector(env(UA.chromeWin));
  await c.collect();
  const App = () => React.createElement("p", null, useDeviceSignals(c)?.device.os ?? "none");
  eq(renderToString(React.createElement(App)), "<p>none</p>");
});

// ---------- server: framework adapters ----------

const { expressSecurity, fastifySecurity, fetchSecurity, requestSecurity } = await import("../src/server/index");
const sigValue = encodeSignals(good);

await check("requestSecurity", () => {
  const r = requestSecurity({ headers: { "x-mgpl-signals": sigValue, "user-agent": "UA", origin: "https://a.b" }, remoteAddress: "::ffff:10.1.1.1" });
  eq(r, { ip: "10.1.1.1", signals: good, userAgent: "UA", origin: "https://a.b", tlsFingerprint: null });
});

// ---------- server: TLS fingerprint from the proxy ----------

const { parseTlsFingerprint, readTlsFingerprint } = await import("../src/server/index");
const ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const ja3 = "773906b0efdefa24a7f2b8eb6985bf37";

await check("parseTlsFingerprint: JA4, JA3, other forms; rejects junk", () => {
  eq(parseTlsFingerprint(ja4), { kind: "ja4", value: ja4 });
  eq(parseTlsFingerprint(` ${ja4.toUpperCase()} `), { kind: "ja4", value: ja4 });
  eq(parseTlsFingerprint("q13i0310h3_55b375c5d22e_cd85d2d88918"), { kind: "ja4", value: "q13i0310h3_55b375c5d22e_cd85d2d88918" });
  eq(parseTlsFingerprint(ja3.toUpperCase()), { kind: "ja3", value: ja3 });
  eq(parseTlsFingerprint("771,4865-4866,0-23-65281,29-23,0"), { kind: "other", value: "771,4865-4866,0-23-65281,29-23,0" });
  for (const bad of [undefined, null, "", "short", "has space here", "<script>", `${ja4}, ${ja4}`, "x".repeat(257)]) eq(parseTlsFingerprint(bad), null);
});
await check("readTlsFingerprint only through a trusted proxy and a configured header", () => {
  const headers = { "X-JA4": ja4 };
  eq(readTlsFingerprint({ headers, header: "x-ja4", trustedHops: 1 }), { kind: "ja4", value: ja4 });
  eq(readTlsFingerprint({ headers: new Headers(headers), header: "X-Ja4", trustedHops: 2 }), { kind: "ja4", value: ja4 });
  eq(readTlsFingerprint({ headers, header: "x-ja4" }), null); // no trusted proxy: any client could send it
  eq(readTlsFingerprint({ headers, header: "x-ja4", trustedHops: 0 }), null);
  eq(readTlsFingerprint({ headers, trustedHops: 1 }), null); // no header configured
  eq(readTlsFingerprint({ headers: {}, header: "x-ja4", trustedHops: 1 }), null); // TLS ended elsewhere
  // a client value the proxy appended to instead of replacing arrives joined ("a, b") and is refused
  eq(readTlsFingerprint({ headers: { "x-ja4": `${ja4}, ${ja4}` }, header: "x-ja4", trustedHops: 1 }), null);
});
await check("fetchSecurity: info, headers, preflight, apply", () => {
  const sec = fetchSecurity({ cors: { origins: ["https://lab.example.in"] }, trustedHops: 1, tlsFingerprintHeader: "x-ja4" });
  const r = sec.handle(new Request("https://api/graphql", { method: "POST", headers: { origin: "https://lab.example.in", "x-forwarded-for": "203.0.113.9", "x-ja4": ja4, [SIGNALS_HEADER]: sigValue } }), "10.0.0.2");
  eq(r.security.ip, "203.0.113.9");
  eq(r.security.tlsFingerprint, { kind: "ja4", value: ja4 });
  eq(r.security.signals, good);
  eq(r.preflight, null);
  eq(r.headers["access-control-allow-origin"], "https://lab.example.in");
  eq(r.headers["x-content-type-options"], "nosniff");
  const pre = sec.handle(new Request("https://api/graphql", { method: "OPTIONS", headers: { origin: "https://lab.example.in", "access-control-request-method": "POST" } }));
  eq(pre.preflight?.status, 204);
  ok(pre.preflight!.headers.get("access-control-allow-headers")!.includes(SIGNALS_HEADER));
  const res = sec.apply(new Response("ok"), r.headers);
  eq(res.headers.get("cache-control"), "no-store");
  const immutable = sec.apply(Response.redirect("https://x.example/", 302), r.headers);
  eq(immutable.headers.get("x-frame-options"), "DENY");
});

await check("expressSecurity on a real Express app", async () => {
  const express = (await import("express")).default;
  const app = express();
  app.use(expressSecurity({ cors: { origins: ["https://lab.example.in"] } }));
  app.post("/graphql", (req, res) => void res.json((req as unknown as { security: unknown }).security));
  const server = app.listen(0);
  await new Promise((r) => server.once("listening", r));
  const port = (server.address() as { port: number }).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/graphql`, { method: "POST", headers: { origin: "https://lab.example.in", [SIGNALS_HEADER]: sigValue } });
    const body = (await res.json()) as { ip: string; signals: DeviceSignals };
    eq(body.signals, good);
    eq(body.ip, "127.0.0.1");
    eq(res.headers.get("access-control-allow-origin"), "https://lab.example.in");
    eq(res.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
    const pre = await fetch(`http://127.0.0.1:${port}/graphql`, { method: "OPTIONS", headers: { origin: "https://lab.example.in", "access-control-request-method": "POST" } });
    eq(pre.status, 204);
    const evil = await fetch(`http://127.0.0.1:${port}/graphql`, { method: "POST", headers: { origin: "https://evil.example" } });
    eq(evil.headers.get("access-control-allow-origin"), null);
  } finally {
    server.close();
  }
});
await check("fastifySecurity on a real Fastify app (applies outside its plugin scope)", async () => {
  const Fastify = (await import("fastify")).default;
  const app = Fastify();
  await app.register(fastifySecurity({ cors: { origins: ["https://*.mgpl.example"] }, headers: { hsts: false } }));
  app.post("/graphql", async (req) => (req as unknown as { security: unknown }).security);
  try {
    const res = await app.inject({ method: "POST", url: "/graphql", headers: { origin: "https://panel.mgpl.example", [SIGNALS_HEADER]: sigValue }, payload: {} });
    const body = res.json() as { signals: DeviceSignals; ip: string; tlsFingerprint: unknown };
    eq(body.signals, good);
    eq(body.ip, "127.0.0.1");
    eq(body.tlsFingerprint, null);
    eq(res.headers["access-control-allow-origin"], "https://panel.mgpl.example");
    eq(res.headers["strict-transport-security"], undefined);
    eq(res.headers["x-frame-options"], "DENY");
    const pre = await app.inject({ method: "OPTIONS", url: "/graphql", headers: { origin: "https://panel.mgpl.example", "access-control-request-method": "POST" } });
    eq(pre.statusCode, 204);
  } finally {
    await app.close();
  }
});
await check("fastifySecurity reads the TLS fingerprint only when the proxy is trusted", async () => {
  const Fastify = (await import("fastify")).default;
  for (const [trustedHops, want] of [[1, { kind: "ja3", value: ja3 }], [0, null]] as const) {
    const app = Fastify();
    await app.register(fastifySecurity({ trustedHops, tlsFingerprintHeader: "x-ja3" }));
    app.post("/graphql", async (req) => (req as unknown as { security: unknown }).security);
    try {
      const res = await app.inject({ method: "POST", url: "/graphql", headers: { "x-ja3": ja3, "x-forwarded-for": "203.0.113.9" }, payload: {} });
      eq((res.json() as { tlsFingerprint: unknown }).tlsFingerprint, want);
    } finally {
      await app.close();
    }
  }
});

console.log(`${passed} passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.error(`  ✗ ${f}`);
  process.exit(1);
}
