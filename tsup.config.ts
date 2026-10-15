import { defineConfig } from "tsup";

// two builds run in parallel, so neither cleans dist/ (the build script does it first)

export default defineConfig([
  {
    entry: { index: "src/index.ts", browser: "src/browser/index.ts", server: "src/server/index.ts" },
    format: ["esm"],
    dts: true,
    target: "es2022",
    splitting: true,
    external: [/^node:/],
  },
  // the optional React hook, marked as a client module for Next.js
  {
    entry: { react: "src/react.ts" },
    format: ["esm"],
    dts: true,
    target: "es2022",
    external: ["react"],
    banner: { js: '"use client";' },
  },
]);
