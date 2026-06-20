// Host-side bundler: resolve npm (node_modules) + CDN (https) imports into one
// self-contained ESM blob via esbuild. Runs in the NETWORK-ALLOWED bundler
// function only; the output blob carries zero unresolved imports, so the runner
// sandbox never needs npm or network.
//
// I/O contract (stdin/stdout JSON) so it is language-agnostic to the caller:
//   stdin : { "entry": "<agent ESM source>", "allowHosts": ["esm.sh", ...],
//             "cdnBase": "https://esm.sh/" }
//   stdout: { "ok": true, "bytes": N, "ms": N, "code": "<bundle>" }
//           { "ok": false, "error": "<message>" }
//
// Resolution model (stateless, no per-session node_modules):
//   - relative / absolute imports: resolved by esbuild normally
//   - explicit https:// imports:   fetched (allowlisted hosts only)
//   - BARE specifiers ("lodash", "@scope/pkg", "react/jsx-runtime"): rewritten
//     to `${cdnBase}<spec>` so any npm package is served as ESM via esm.sh.
//   This makes "npm or cdnjs" a single path and the bundler fully stateless.
import esbuild from "esbuild";
import { readFileSync } from "node:fs";

function readStdin() {
  return JSON.parse(readFileSync(0, "utf8"));
}

const DEFAULT_ALLOW = new Set([
  "esm.sh",
  "cdn.jsdelivr.net",
  "cdnjs.cloudflare.com",
  "unpkg.com",
  "esm.run",
]);

async function main() {
  const { entry, allowHosts, cdnBase } = readStdin();
  if (typeof entry !== "string" || !entry.trim()) {
    process.stdout.write(JSON.stringify({ ok: false, error: "empty entry" }));
    return;
  }
  const allow = new Set([...(allowHosts ?? []), ...DEFAULT_ALLOW]);
  const base = cdnBase || "https://esm.sh/";

  // Rewrite bare npm specifiers to the CDN so the bundler needs no node_modules.
  const barePlugin = {
    name: "secure-repl-bare-to-cdn",
    setup(build) {
      // node: builtins are provided by the secure-exec runtime; keep external.
      build.onResolve({ filter: /^node:/ }, (a) => ({ path: a.path, external: true }));
      // Anything else that is not relative, absolute, or http(s) is a bare spec.
      build.onResolve({ filter: /^[^./]/ }, (a) => {
        if (/^https?:\/\//.test(a.path) || a.namespace === "http-url") return null;
        const url = new URL(a.path, base).toString();
        const host = new URL(url).host;
        if (!allow.has(host)) throw new Error(`CDN host not allowed: ${host}`);
        return { path: url, namespace: "http-url" };
      });
    },
  };

  // CDN fetch plugin. Only allowlisted hosts may be fetched (supply-chain +
  // SSRF guard). esm.sh UA-sniffs, so present a browser UA.
  const httpPlugin = {
    name: "secure-repl-http",
    setup(build) {
      build.onResolve({ filter: /^https?:\/\// }, (a) => {
        const host = new URL(a.path).host;
        if (!allow.has(host)) throw new Error(`CDN host not allowed: ${host}`);
        return { path: a.path, namespace: "http-url" };
      });
      build.onResolve({ filter: /.*/, namespace: "http-url" }, (a) => ({
        path: new URL(a.path, a.importer).toString(),
        namespace: "http-url",
      }));
      build.onLoad({ filter: /.*/, namespace: "http-url" }, async (a) => {
        const host = new URL(a.path).host;
        if (!allow.has(host)) throw new Error(`CDN host not allowed: ${host}`);
        const res = await fetch(a.path, {
          headers: { "User-Agent": "Mozilla/5.0", Accept: "*/*" },
        });
        if (!res.ok) throw new Error(`GET ${a.path} -> ${res.status}`);
        return { contents: await res.text(), loader: "js" };
      });
    },
  };

  const t0 = Date.now();
  const result = await esbuild.build({
    stdin: { contents: entry, resolveDir: process.cwd(), loader: "js", sourcefile: "agent-entry.mjs" },
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    write: false,
    legalComments: "none",
    plugins: [barePlugin, httpPlugin],
  });
  const code = result.outputFiles[0].text;
  process.stdout.write(JSON.stringify({ ok: true, bytes: code.length, ms: Date.now() - t0, code }));
}

main().catch((e) => {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e?.stack || e) }));
});
