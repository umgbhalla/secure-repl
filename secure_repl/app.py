"""secure-repl infra — production Modal app (multi-tenant).

Two-stage pipeline for running untrusted, agent-authored REPL code with npm/CDN
package support and durable park/resume:

  bundle()   network-allowed Modal Function. Resolves npm + allowlisted-CDN
             imports into one self-contained ESM blob (esbuild). Output carries
             zero unresolved imports, so the runner needs neither npm nor net.

  run_repl() VM Sandbox (real Linux kernel, required for secure-exec's sidecar
             openat2/namespace primitives) with a DENY-NET permission policy.
             Loads the blob into secure-exec, runs it, and parks/resumes session
             state through a mounted Modal Volume.

Tenancy + auth:
  Every call carries an opaque API key. The key maps to a tenant via a Modal
  Secret (SECURE_REPL_KEYS = {"<key>": "<tenant>"}). Authorization is structural:
  durable state lives at /vol/<tenant>/<session> where <tenant> comes ONLY from
  the validated key — a client cannot name another tenant's namespace.

Scaling:
  Both functions autoscale. run_repl is an IO-bound orchestrator (it spawns a
  Sandbox then waits), so one container fans out to many concurrent sessions.

Deploy:   modal deploy secure_repl/app.py
Invoke:   see secure_repl/client.py / README.md

Pinned: Modal SDK 1.5.x, node 22, esbuild 0.28.1, secure-exec 0.3.0.
"""

import hmac
import json
import os
import re
from pathlib import Path

import modal

APP_NAME = "secure-repl"
ASSETS = Path(__file__).parent / "assets"
AUTH_SECRET_NAME = "secure-repl-auth"  # env SECURE_REPL_KEYS = {"<key>": "<tenant>"}

app = modal.App(APP_NAME)

# Durable session state. Layout: /<tenant>/<session>/fs.json (+ _input/_result).
state_volume = modal.Volume.from_name("secure-repl-state", create_if_missing=True)
auth_secret = modal.Secret.from_name(AUTH_SECRET_NAME)

# ---- Auth / tenancy ---------------------------------------------------------
_ID_RE = re.compile(r"\A[A-Za-z0-9_-]{1,128}\Z")  # no dots/slashes -> no traversal


def _authenticate(token: str | None) -> str:
    """Map an API key to a tenant via the Secret. Raises on bad/missing key.

    Linear constant-time scan over the key table.
    # ponytail: linear scan, fine for <10k tenants; index by key prefix if it grows.
    """
    keys = json.loads(os.environ["SECURE_REPL_KEYS"])
    token = token or ""
    match = ""
    for key, tenant in keys.items():
        if hmac.compare_digest(key, token):
            match = tenant
    if not match:
        raise PermissionError("invalid or missing api key")
    return match


def _safe_id(session: str) -> str:
    if not _ID_RE.match(session or ""):
        raise ValueError("session id must match [A-Za-z0-9_-]{1,128}")
    return session


# ---- Images -----------------------------------------------------------------
# Bundler image: node + esbuild only. Network-allowed at call time so it can
# fetch npm metadata + CDN modules. Pinned, content-addressed, cached by Modal.
bundler_image = (
    modal.Image.from_registry("node:22-slim", add_python="3.11")
    .workdir("/srv")
    .add_local_file(ASSETS / "bundler.package.json", "/srv/package.json", copy=True)
    .run_commands("cd /srv && npm install --no-audit --no-fund")
    .add_local_file(ASSETS / "bundler.mjs", "/srv/bundler.mjs", copy=True)
)

# Runner image: node + secure-exec. Runs inside a VM Sandbox with deny-net.
# Uses full node:22 (NOT -slim): secure-exec's native Rust sidecar binary needs
# shared libs (e.g. libstdc++) that the slim image omits, which makes the
# sidecar child exit on startup (surfaces as an EPIPE on the stdio transport).
runner_image = (
    modal.Image.from_registry("node:22", add_python="3.11")
    .workdir("/srv")
    .add_local_file(ASSETS / "runner.package.json", "/srv/package.json", copy=True)
    .run_commands("cd /srv && npm install --no-audit --no-fund")
    .add_local_file(ASSETS / "runner.mjs", "/srv/runner.mjs", copy=True)
)

# Resource + safety defaults. Lowest sensible spec for an execution substrate:
# the sandbox only runs one short-lived bundle, so it does not need a fat box.
# ponytail: 1 CPU / 1 GiB is the node+sidecar floor; bump if the bench OOMs.
RUNNER_CPU = 1
RUNNER_MEM_MB = 1024
RUNNER_TIMEOUT_S = 300


@app.function(
    image=bundler_image,
    secrets=[auth_secret],
    timeout=120,
    max_containers=20,
    scaledown_window=60,
)
@modal.concurrent(max_inputs=10)
def bundle(auth_token: str, entry: str, allow_hosts: list[str] | None = None) -> dict:
    """Resolve npm + CDN imports in `entry` into one self-contained ESM blob.

    Returns {ok, bytes, ms, code} | {ok: False, error}. Runs network-allowed.
    """
    import subprocess

    try:
        _authenticate(auth_token)
    except PermissionError as e:
        return {"ok": False, "stage": "auth", "error": str(e)}

    payload = json.dumps({"entry": entry, "allowHosts": allow_hosts or []})
    proc = subprocess.run(
        ["node", "/srv/bundler.mjs"],
        input=payload,
        capture_output=True,
        text=True,
        cwd="/srv",
        timeout=110,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": f"bundler exited {proc.returncode}: {proc.stderr[-500:]}"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"bad bundler output: {proc.stdout[:500]}"}


# Live channel layout (runner-local tiny files). Host<->guest goes over the
# Sandbox filesystem API (sb.filesystem.write_text/read_text), which IS supported
# under Modal's VM runtime as of SDK >=1.4 — no size cap, no compression, no argv
# limit. (sb.reload_volumes() stays unsupported under the VM runtime, but reuse
# does not need it: the request is written straight into the guest fs.)
# Protocol: write REQ_JSON, then bump REQ_SEQ. The runner loop polls REQ_SEQ,
# re-reads REQ_JSON, runs on the persistent NodeRuntime (NO microVM boot), and
# writes RES_FILE + RES_SEQ. We then busy-wait (one exec) for the matching
# RES_SEQ and read RES_FILE back over the filesystem API.
_RUNNER_DIR = "/srv"
_REQ_JSON = f"{_RUNNER_DIR}/req.json"   # request body; runner reads on each seq bump
_REQ_SEQ = f"{_RUNNER_DIR}/req.seq"     # orchestrator bumps to signal a new request
_RES_FILE = f"{_RUNNER_DIR}/res.json"   # result body; orchestrator reads it back
_RES_SEQ = f"{_RUNNER_DIR}/res.seq"     # runner bumps to match REQ_SEQ when done

# How long an already-booted sandbox may take to return a result before we give
# up and rebuild. Generous — a single eval is sub-second once warm.
_EXEC_WAIT_S = 90

# Busy-wait shell: block until RES_SEQ equals the request token (or time out).
# Just a barrier — the result body is read back over the filesystem API, so this
# exec carries no payload.
_WAIT_EXEC = (
    'i=0; '
    'while [ "$(cat {res_seq} 2>/dev/null)" != "$NSEQ" ]; do '
    '  i=$((i+1)); [ "$i" -gt "$MAXI" ] && {{ echo "__TIMEOUT__"; exit 0; }}; '
    '  sleep 0.005; '
    'done; echo "__OK__"'
).format(res_seq=_RES_SEQ)


def _exec_status(sb, script: str, env: dict | None = None,
                 timeout: int | None = None) -> str:
    """Run a one-shot barrier command inside a live sandbox; return its stdout."""
    p = sb.exec("bash", "-c", script, env=env or {}, timeout=timeout)
    out = p.stdout.read()
    p.wait()
    return out


def _serve_via_live_sandbox(sb, req: dict, wait_s: int) -> dict | None:
    """Hand a fresh request to a running sandbox over the filesystem API and read
    the result back. Returns the result dict, or None if it timed out / failed
    (caller then rebuilds). No microVM boot on this path."""
    import time as _t

    sb.filesystem.write_text(json.dumps(req), _REQ_JSON)
    next_seq = str(int(_t.time() * 1000))  # strictly-increasing token (> boot's 1)
    sb.filesystem.write_text(next_seq, _REQ_SEQ)
    maxi = int(wait_s / 0.005)
    status = _exec_status(
        sb, _WAIT_EXEC, env={"NSEQ": next_seq, "MAXI": str(maxi)}, timeout=wait_s + 10
    ).strip()
    if "__OK__" not in status:
        return None
    try:
        return json.loads(sb.filesystem.read_text(_RES_FILE))
    except (json.JSONDecodeError, Exception):
        return None


@app.function(
    image=runner_image,
    secrets=[auth_secret],
    volumes={"/vol": state_volume},
    timeout=RUNNER_TIMEOUT_S + 60,
    max_containers=50,
    scaledown_window=120,
)
# One session per orchestrator container: Volume.commit() is process-global, so
# in-process concurrency races on shared-mount writes (EPERM). Scale horizontally
# by container instead (Modal spins up to max_containers).
#
# PERSISTENT-SANDBOX REUSE: we keep the VM Sandbox (and its secure-exec
# NodeRuntime) ALIVE across calls for the same (tenant, session). The live
# sandbox's object_id is persisted on the Volume at <state_dir>/sandbox.id. On a
# call we first try modal.Sandbox.from_id(stored_id); if it's still running we
# hand it a fresh request over an in-sandbox file channel (write req.json, bump
# req.seq, poll res.seq) — execute-only, NO microVM boot. If missing/dead we
# create a fresh long-lived sandbox, run the bootstrap request, and store its id.
def run_repl(auth_token: str, session_id: str, bundle_code: str, mode: str = "fresh",
             persist: bool = False) -> dict:
    """Run a bundle inside a deny-net VM Sandbox, reusing a live sandbox +
    NodeRuntime per (tenant, session) when one exists.

    `mode`:    "fresh" (ignore prior state) | "resume" (rehydrate the session dir).
    `persist`: snapshot guest state to the Volume after the run (durable park).
               Forced on for resume. Off by default so a plain stateless eval
               skips the extra snapshot rt.run() round-trip.
    Returns the runner contract dict (value, saved, rehydrated, ...).
    """
    try:
        tenant = _authenticate(auth_token)
        session_id = _safe_id(session_id)
    except (PermissionError, ValueError) as e:
        return {"ok": False, "stage": "auth", "error": str(e)}

    import base64

    # Namespace is derived from the validated tenant, NOT from client input.
    state_dir = f"/vol/{tenant}/{session_id}"
    in_path = f"{state_dir}/_input.json"   # bootstrap request (boot only)
    out_path = f"{state_dir}/_result.json"
    id_path = f"{state_dir}/sandbox.id"

    persist = bool(persist) or mode == "resume"
    req = {"bundle": bundle_code, "stateDir": state_dir, "mode": mode, "persist": persist}

    # ---- Fast path: reuse a live sandbox for this session (execute-only). ----
    state_volume.reload()
    stored_id = None
    if os.path.exists(id_path):
        try:
            with open(id_path) as f:
                stored_id = f.read().strip() or None
        except OSError:
            stored_id = None

    if stored_id:
        try:
            sb = modal.Sandbox.from_id(stored_id)
            if sb.poll() is None:  # still running -> hand it a fresh request
                result = _serve_via_live_sandbox(sb, req, _EXEC_WAIT_S)
                if result is not None:
                    return result  # served on the live runtime, NO microVM boot
                # died / timed out / unreadable -> fall through and rebuild.
        except Exception:
            pass  # stale/invalid id -> create a fresh sandbox below.

    # ---- Slow path: no live sandbox -> create a fresh long-lived one. --------
    # Sandbox image, built from the assets baked into THIS container (/srv).
    # Built at runtime (not module scope) because module-level local-file mounts
    # are re-read when Sandbox.create reloads the image — and the local source
    # path is gone in a remote container. base64-from-/srv sidesteps that; the
    # content hash is stable across calls, so Modal builds it once then caches.
    def _b64(p: str) -> str:
        with open(p, "rb") as f:
            return base64.b64encode(f.read()).decode()

    sandbox_image = (
        modal.Image.from_registry("node:22")
        .workdir("/srv")
        .run_commands(f"echo {_b64('/srv/package.json')} | base64 -d > /srv/package.json")
        .run_commands("cd /srv && npm install --no-audit --no-fund")
        .run_commands(f"echo {_b64('/srv/runner.mjs')} | base64 -d > /srv/runner.mjs")
    )

    # Stage the bootstrap request on the Volume (the runner reads INPUT_FILE on
    # boot and mirrors its result to OUTPUT_FILE and to the live RES channel).
    os.makedirs(state_dir, exist_ok=True)
    with open(in_path, "w") as f:
        json.dump(req, f)
    state_volume.commit()

    sb = modal.Sandbox.create(
        "bash",
        "-lc",
        "node /srv/runner.mjs",
        app=app,
        image=sandbox_image,
        cpu=RUNNER_CPU,
        memory=RUNNER_MEM_MB,
        timeout=RUNNER_TIMEOUT_S,
        volumes={"/vol": state_volume},
        experimental_options={"vm_runtime": True},  # real kernel for sidecar
        env={
            "INPUT_FILE": in_path,    # bootstrap request payload (read at boot)
            "OUTPUT_FILE": out_path,  # mirrored bootstrap result (durable)
            # REQ_JSON defaults to /srv/req.json in the runner; reuse-path
            # requests are written there directly via the filesystem API.
            "RUNNER_DIR": _RUNNER_DIR,
            "RUNNER_IDLE_MS": "60000",
        },
    )

    # Persist the live sandbox id so subsequent calls reuse it (execute-only).
    try:
        with open(id_path, "w") as f:
            f.write(sb.object_id)
        state_volume.commit()
    except Exception:
        pass

    # The bootstrap request is served as RES_SEQ == 1. Wait for it (one blocking
    # exec barrier) WITHOUT terminating the sandbox — we keep it alive for reuse.
    # Boot includes image build (first time) + microVM start, so allow the full
    # runner timeout, then read the result body over the filesystem API.
    boot_maxi = int((RUNNER_TIMEOUT_S - 10) / 0.01)
    boot_wait = (
        'i=0; '
        'while [ "$(cat {res_seq} 2>/dev/null)" != "1" ]; do '
        '  i=$((i+1)); [ "$i" -gt "$MAXI" ] && {{ echo "__TIMEOUT__"; exit 0; }}; '
        '  sleep 0.01; '
        'done; echo "__OK__"'
    ).format(res_seq=_RES_SEQ)
    try:
        status = _exec_status(
            sb, boot_wait, env={"MAXI": str(boot_maxi)}, timeout=RUNNER_TIMEOUT_S
        ).strip()
        if "__OK__" in status:
            return json.loads(sb.filesystem.read_text(_RES_FILE))
    except Exception:
        pass

    # Fallback: read the Volume-mirrored bootstrap result.
    state_volume.reload()
    if os.path.exists(out_path):
        try:
            with open(out_path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return {"ok": False, "error": "no bootstrap result (runner did not emit seq 1)"}


@app.local_entrypoint()
def main(code: str = "", session: str = "smoke", mode: str = "fresh"):
    """Smoke test: bundle a tiny npm+CDN snippet and run it end-to-end.

    Reads the API key from $SECURE_REPL_TOKEN (must exist in the auth Secret).
    """
    token = os.environ.get("SECURE_REPL_TOKEN", "")
    if not code:
        code = (
            'import { chunk } from "lodash";\n'
            'import pluralize from "https://esm.sh/pluralize";\n'
            'globalThis.__return({ grouped: chunk([1,2,3,4,5],2), plural: pluralize("repl",3,true) });'
        )
    b = bundle.remote(token, code)
    assert b.get("ok"), f"bundle failed: {b}"
    print(f"bundled: {b['bytes']} bytes in {b['ms']}ms")
    r = run_repl.remote(token, session, b["code"], mode)
    print("run_repl:", json.dumps(r, indent=2))
