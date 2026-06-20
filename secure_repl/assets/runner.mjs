// In-sandbox runner: load a self-contained bundle into secure-exec, optionally
// rehydrate prior session state, run, then snapshot state back out. Runs inside
// a VM Sandbox with a DENY-NET permission policy. State crosses sandboxes only
// through the mounted Modal Volume (a host-side {path:b64} manifest).
//
// The kernel VFS persists across multiple run() calls on the same NodeRuntime,
// so we use three explicit phases on one runtime:
//   1. rehydrate  - materialize prior state into GUEST_STATE (resume only)
//   2. execute    - run the agent bundle, capture its __return value
//   3. snapshot   - walk GUEST_STATE, capture {path:b64} for the volume
//
// I/O contract (Volume files; stdin to a VM Sandbox is unreliable):
//   env INPUT_FILE  -> { "bundle": "<esm blob>", "stateDir": "/vol/<session>", "mode": "..." }
//   env OUTPUT_FILE -> { "ok": true, "value": <return>, "stdout": "...", "exitCode": N,
//                        "rehydrated": N, "saved": [paths] } | { "ok": false, "error": "..." }
// Also echoes the result JSON on stdout as a convenience.
import { NodeRuntime } from "secure-exec";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";

const GUEST_STATE = "/home/user/state";
const INPUT_FILE = process.env.INPUT_FILE;
const OUTPUT_FILE = process.env.OUTPUT_FILE;

// secure-exec talks to its sidecar over a stdio frame transport; during teardown
// a stray EPIPE can surface as an async socket error. Once we've written the
// result file, such late errors are harmless — don't let them crash the process.
let __emitted = false;
process.on("uncaughtException", (e) => {
  if (__emitted && (e?.code === "EPIPE" || /EPIPE/.test(String(e)))) return;
  if (!__emitted) { try { emit({ ok: false, error: String(e?.stack || e) }); } catch {} }
  process.exit(__emitted ? 0 : 1);
});

function readInput() {
  return JSON.parse(readFileSync(INPUT_FILE, "utf8"));
}
function emit(obj) {
  const s = JSON.stringify(obj);
  if (OUTPUT_FILE) writeFileSync(OUTPUT_FILE, s);
  try { process.stdout.write(s); } catch {}
  __emitted = true;
}

const SNAPSHOT_WALKER = `
  import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
  const snap = {};
  const walk = (d) => { if (!existsSync(d)) return; for (const n of readdirSync(d)) {
    const p = d + "/" + n; statSync(p).isDirectory() ? walk(p) : (snap[p] = readFileSync(p).toString("base64")); } };
  walk(${JSON.stringify(GUEST_STATE)});
  globalThis.__return(snap);
`;

function rehydrateProgram(seedJson) {
  return `
    import { mkdirSync, writeFileSync } from "node:fs";
    import { dirname } from "node:path";
    const seed = JSON.parse(${JSON.stringify(seedJson)});
    let n = 0;
    for (const [p, b64] of Object.entries(seed)) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, Buffer.from(b64, "base64")); n++; }
    globalThis.__return(n);
  `;
}

async function main() {
  const { bundle, stateDir, mode } = readInput();
  if (!bundle) return emit({ ok: false, error: "no bundle" });

  let seedJson = "{}";
  let rehydrated = 0;
  if (mode === "resume" && stateDir && existsSync(`${stateDir}/fs.json`)) {
    seedJson = readFileSync(`${stateDir}/fs.json`, "utf8");
    rehydrated = Object.keys(JSON.parse(seedJson)).length;
  }

  // secure-exec's DEFAULT permission policy DENIES network (guest cannot reach
  // the network until you opt in with { network: "allow" }). For untrusted
  // agent code we keep the secure default by omitting the policy entirely.
  const rt = await NodeRuntime.create();
  try {
    // Phase 1: rehydrate prior state (resume only).
    if (mode === "resume" && rehydrated > 0) {
      await rt.run(rehydrateProgram(seedJson));
    }

    // Phase 2: execute the agent bundle.
    const res = await rt.run(bundle);

    // Phase 3: snapshot GUEST_STATE back out.
    const snapRes = await rt.run(SNAPSHOT_WALKER);
    const snap = snapRes.value || {};

    if (stateDir) {
      mkdirSync(stateDir, { recursive: true });
      writeFileSync(`${stateDir}/fs.json`, JSON.stringify(snap));
    }

    emit({
      ok: true,
      value: res.value,
      stdout: res.stdout || "",
      exitCode: res.exitCode ?? 0,
      rehydrated,
      saved: Object.keys(snap),
    });
  } catch (e) {
    emit({ ok: false, error: String(e?.stack || e) });
  } finally {
    await rt.dispose();
  }
}

main();
