# AGENTS.md — @mgpl-diagnostics/security-kit

Security primitives used on **both sides**: the frontend (`/browser`, through `@mgpl-diagnostics/client`
and apps) and the backend (`/server`, through `mgpl-diagnostics/api` and auth flows). **A library: no
server, no GraphQL, no UI, zero runtime dependencies.**

## Map

```
src/index.ts             shared entry (browser, Node.js, workers, React Native)
src/shared/types.ts      DeviceSignals, DeviceInfo
src/shared/constants.ts  SIGNALS_HEADER ("x-mgpl-signals"), SIGNAL_LIMITS, ID_PATTERN, FINGERPRINT_PATTERN
src/shared/crypto.ts     base64url, randomBytes/randomId, sha256Hex, constantTimeEqual, canonicalJson (Web Crypto only)
src/shared/signals.ts    encodeSignals, signalHeaders, parseSignals/decodeSignals (validate untrusted input)
src/browser/             "/browser": storage.ts (web/memory/custom), device.ts (deviceInfo, fingerprint inputs),
                         collect.ts (createSignalCollector: collect, headers, subscribe/getSnapshot),
                         adapters.ts (signalFetch, mergeSignalHeaders, axiosSignals, kySignals, apolloSignals, signalStore)
src/react.ts             "/react": useDeviceSignals (React is an optional peer)
src/server/              "/server": signals.ts (readSignals, bindSignals, checkSignals, decide), ip.ts (clientIp),
                         tls.ts (readTlsFingerprint: JA4/JA3 from a trusted proxy header),
                         headers.ts (securityHeaders, corsPolicy), redact.ts (redact, maskEmail, maskPhone),
                         adapters.ts (requestSecurity, fetchSecurity, expressSecurity, fastifySecurity)
scripts/test.ts          every part; browser code runs on simulated environments
scripts/check-dist.mjs   the built main and /browser bundles import no Node.js modules
```

## Rules

1. **The shared and browser parts use no Node.js APIs** (no `node:*`, no `Buffer`): only Web Crypto,
   `TextEncoder`, `btoa`/`atob`. `npm run typecheck` compiles them without `@types/node`, and CI runs
   `scripts/check-dist.mjs` on the bundles.
2. **No runtime dependencies; works with every library.** Adapters match a library's hook shape
   structurally and never import it (axios, ky, Apollo, Express, Fastify…). React is the one optional
   peer, used only by `/react`. Prefer a generic contract (`fetch`, headers, `subscribe`/`getSnapshot`)
   over a new per-library adapter, and test every adapter (a real Express and Fastify app in `npm test`).
3. **Signals stay coarse.** No canvas, audio, WebGL, font or IP probing, nothing sent to third parties.
   Anything new that is collected goes in the README table "What is collected" in the same PR.
4. **Never store raw ids or tokens.** The server keeps `bindSignals()` output (SHA-256 of ids).
5. **Everything read from a request is untrusted.** `decodeSignals` / `readSignals` never throw, cap
   sizes, and return `null` for anything malformed. Keep it that way and add a test for each new field.
6. The signal format is a contract between client and api: `SIGNALS_HEADER`, field names and `v: 1`.
   Add optional fields; a breaking change needs `v: 2` and both versions accepted during the rollout.
7. Verdict names (`same`, `changed`, `other-device`, `missing`, `unbound`) are public: add, never rename.
8. Token logic (passwords, sessions, JWT) stays in **auth-kit**; permissions stay in auth-kit.
9. Never commit secrets, `.env` files or real patient data (tests use fictional values).

## Commands

```bash
npm run typecheck && npm test && npm run build && node scripts/check-dist.mjs
npm run llms      # regenerate llms-full.txt (CI fails when it is stale)
```

## Repository rules

`main` takes pull requests only: squash merge, 1 code-owner review (`@BackStacked`), the `ci` check
required. Rules come from `mgpl-diagnostics/.github` (`scripts/protect-repos.mjs`).

## Licence

All rights reserved (see LICENSE).
