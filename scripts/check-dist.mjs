// After `npm run build`: the main and /browser bundles (and every chunk they import) must not load
// Node.js modules, so they run in browsers, workers and React Native. /server may.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const seen = new Set();
const bad = [];
function walk(file) {
  if (seen.has(file)) return;
  seen.add(file);
  const src = readFileSync(file, "utf8");
  for (const m of src.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
    const spec = m[1];
    if (spec.startsWith("node:") || /^(crypto|net|fs|path|buffer|os)$/.test(spec)) bad.push(`${file} imports ${spec}`);
    else if (spec.startsWith(".")) walk(join(dirname(file), spec));
  }
  if (/\bBuffer\./.test(src)) bad.push(`${file} uses Buffer`);
}
walk("dist/index.js");
walk("dist/browser.js");
if (bad.length) {
  console.error(bad.join("\n"));
  process.exit(1);
}
console.log(`dist: ${seen.size} browser-safe files`);
