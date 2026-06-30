// Persistent in-sandbox runner: create the NodeRuntime ONCE, then service many
// requests on it until idle timeout or a shutdown sentinel. This keeps the VM
// Sandbox AND the secure-exec NodeRuntime alive across calls to the same
// (tenant, session), so 2nd+ calls are execute-only (no microVM boot).
//
// The kernel VFS persists across run() calls on one NodeRuntime, so a session's
// in-guest state is naturally retained between calls without any Volume
// round-trip. We still snapshot to the Volume each call for DURABILITY (so a
// fresh sandbox can resume the session if this one dies / is reaped).
//
// LIVE I/O CHANNEL (host <-> guest) — all over sb.exec, which is the ONLY
// host->guest channel that works under Modal's VM runtime (cloud-hypervisor):
// sb.open()'s FilesystemExecution API and sb.reload_volumes() are both
// unsupported there. So:
//   - REQUEST  (incl. the bundle) is delivered by the orchestrator INTO the
//     guest's own fs at REQ_JSON (a local path, default /srv/req.json) via an
//     sb.exec that decodes a gzip+base64 payload (one exec for the common case;
//     chunked appends for very large bundles). Then the same exec bumps SEQ.
//   - SEQ      is a tiny local file (/srv/req.seq) the orchestrator bumps; this
//     loop polls it.
//   - RESULT   is written by this loop to /srv/res.json (+ /srv/res.seq); the
//     orchestrator reads it back via sb.exec stdout (no size cap).
//
// The FIRST request is seeded via env INPUT_FILE (a Volume file) so the boot
// call carries its payload without an extra round-trip; it is served as seq 1.
import { NodeRuntime } from "secure-exec";
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  renameSync,
} from "node:fs";

const DIR = process.env.RUNNER_DIR || "/srv";
const REQ_SEQ = `${DIR}/req.seq`; // local; orchestrator bumps via sb.exec
const RES_FILE = `${DIR}/res.json`; // local; orchestrator reads via sb.exec
const RES_SEQ = `${DIR}/res.seq`; // local
const STOP_FILE = `${DIR}/stop`;
const READY_FILE = `${DIR}/ready`;

// REQ_JSON: local path where the orchestrator materializes each request (via
// sb.exec) before bumping the seq. The loop re-reads this on every seq bump.
const REQ_JSON = process.env.REQ_JSON || `${DIR}/req.json`;

const INPUT_FILE = process.env.INPUT_FILE; // bootstrap (first) request, on Volume
const OUTPUT_FILE = process.env.OUTPUT_FILE; // bootstrap result mirror, on Volume
const IDLE_MS = parseInt(process.env.RUNNER_IDLE_MS || "60000", 10);
const POLL_MS = parseInt(process.env.RUNNER_POLL_MS || "10", 10);

const GUEST_STATE = "/home/user/state";

// secure-exec talks to its sidecar over a stdio frame transport; during teardown
// a stray EPIPE can surface as an async socket error — keep it from crashing us.
process.on("uncaughtException", (e) => {
  if (e?.code === "EPIPE" || /EPIPE/.test(String(e))) return;
  try {
    writeFileSync(`${DIR}/fatal.log`, String(e?.stack || e));
  } catch {}
});

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

function readSeq(path) {
  try {
    const v = parseInt(readFileSync(path, "utf8").trim(), 10);
    return Number.isFinite(v) ? v : 0;
  } catch {
    return 0;
  }
}

// Atomic write: tmp then rename (atomic on same fs) so a reader never sees a
// half-written file.
function atomicWrite(path, str) {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, str);
  renameSync(tmp, path);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Run one request against the live runtime. Mirrors the original 3-phase flow:
//   rehydrate (resume only) -> execute bundle -> snapshot GUEST_STATE to Volume.
// Because the runtime persists, an in-sandbox 2nd call to the same session does
// NOT need to rehydrate from the Volume — its state is already live; we only
// rehydrate when explicitly asked (mode === "resume") and this is the runtime's
// FIRST served call (otherwise the live VFS is the source of truth).
async function handle(rt, req, alreadyServed) {
  const { bundle, stateDir, mode, persist } = req;
  if (!bundle) return { ok: false, error: "no bundle" };

  let rehydrated = 0;
  if (mode === "resume" && !alreadyServed && stateDir && existsSync(`${stateDir}/fs.json`)) {
    const seedJson = readFileSync(`${stateDir}/fs.json`, "utf8");
    rehydrated = Object.keys(JSON.parse(seedJson)).length;
    if (rehydrated > 0) await rt.run(rehydrateProgram(seedJson));
  }

  const res = await rt.run(bundle);

  // Snapshot GUEST_STATE to the Volume for durability ONLY when asked (persist
  // or resume). For a plain stateless eval this skips a whole rt.run() round-trip
  // to the sidecar — the live VFS still holds state for in-session reuse anyway.
  const doPersist = persist === true || mode === "resume";
  let saved = [];
  if (doPersist) {
    const snapRes = await rt.run(SNAPSHOT_WALKER);
    const snap = snapRes.value || {};
    saved = Object.keys(snap);
    if (stateDir) {
      try {
        mkdirSync(stateDir, { recursive: true });
        writeFileSync(`${stateDir}/fs.json`, JSON.stringify(snap));
      } catch {}
    }
  }

  return {
    ok: true,
    value: res.value,
    stdout: res.stdout || "",
    exitCode: res.exitCode ?? 0,
    rehydrated,
    saved,
  };
}

async function serve(rt, req, served) {
  let result;
  try {
    result = await handle(rt, req, served > 0);
  } catch (e) {
    result = { ok: false, error: String(e?.stack || e) };
  }
  return result;
}

async function main() {
  // DENY-NET by default: omit the policy => secure-exec denies network.
  const rt = await NodeRuntime.create();
  let served = 0;

  try {
    // --- Bootstrap request (seeded on the Volume by the creating call). -----
    if (INPUT_FILE && existsSync(INPUT_FILE)) {
      let bootReq = null;
      try {
        bootReq = JSON.parse(readFileSync(INPUT_FILE, "utf8"));
      } catch {}
      if (bootReq) {
        const result = await serve(rt, bootReq, served);
        served++;
        const s = JSON.stringify(result);
        if (OUTPUT_FILE) {
          try {
            writeFileSync(OUTPUT_FILE, s);
          } catch {}
        }
        atomicWrite(RES_FILE, s);
        atomicWrite(RES_SEQ, "1");
      }
    }

    // Signal readiness (after bootstrap so a reuse caller knows seq 1 is done).
    try {
      atomicWrite(READY_FILE, "1");
    } catch {}

    // --- Live loop: serve req.seq bumps until idle / stop. ------------------
    let lastSeq = readSeq(RES_SEQ); // 1 after bootstrap, else 0
    let idleSince = Date.now();
    while (true) {
      if (existsSync(STOP_FILE)) break;
      const reqSeq = readSeq(REQ_SEQ);
      if (reqSeq > lastSeq) {
        let req = null;
        try {
          if (REQ_JSON && existsSync(REQ_JSON)) {
            req = JSON.parse(readFileSync(REQ_JSON, "utf8"));
          }
        } catch {}
        const result = req
          ? await serve(rt, req, served)
          : { ok: false, error: "unreadable request (volume not reloaded?)" };
        served++;
        atomicWrite(RES_FILE, JSON.stringify(result));
        atomicWrite(RES_SEQ, String(reqSeq));
        lastSeq = reqSeq;
        idleSince = Date.now();
      } else {
        if (Date.now() - idleSince > IDLE_MS) break;
        await sleep(POLL_MS);
      }
    }
  } finally {
    try {
      await rt.dispose();
    } catch {}
  }
}

main();
