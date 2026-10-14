import { defineConfig } from "tsup";

export default defineConfig({
  entry: { index: "src/index.ts", browser: "src/browser/index.ts", server: "src/server/index.ts" },
  format: ["esm"],
  dts: true,
  target: "es2022",
  clean: true,
  splitting: true,
  external: [/^node:/],
});
