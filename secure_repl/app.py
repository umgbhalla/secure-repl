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

Pinned: Modal SDK 1.3.x, node 22, esbuild 0.28.1, secure-exec 0.3.0.
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
# by container instead (Modal spins up to max_containers). The orchestrator is
# cheap — it just spawns a sandbox and waits — so a container apiece is fine.
# ponytail: per-container isolation, revisit if orchestrator idle cost matters.
def run_repl(auth_token: str, session_id: str, bundle_code: str, mode: str = "fresh") -> dict:
    """Run a bundle inside a deny-net VM Sandbox with park/resume via Volume.

    `mode`: "fresh" (ignore prior state) | "resume" (rehydrate the session dir).
    Returns the runner contract dict (value, saved, rehydrated, ...).
    """
    try:
        tenant = _authenticate(auth_token)
        session_id = _safe_id(session_id)
    except (PermissionError, ValueError) as e:
        return {"ok": False, "stage": "auth", "error": str(e)}

    import base64

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

    # Namespace is derived from the validated tenant, NOT from client input.
    state_dir = f"/vol/{tenant}/{session_id}"
    in_path = f"{state_dir}/_input.json"
    out_path = f"{state_dir}/_result.json"

    # Stage input on the Volume (robust for large blobs; stdin to a VM Sandbox
    # is unreliable). The runner reads INPUT_FILE and writes OUTPUT_FILE.
    os.makedirs(state_dir, exist_ok=True)
    with open(in_path, "w") as f:
        json.dump({"bundle": bundle_code, "stateDir": state_dir, "mode": mode}, f)
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
        env={"INPUT_FILE": in_path, "OUTPUT_FILE": out_path},
    )
    sb.wait()
    out = sb.stdout.read()
    err = sb.stderr.read()
    sb.terminate()

    # Prefer the Volume result file; fall back to stdout.
    state_volume.reload()
    result = None
    if os.path.exists(out_path):
        try:
            with open(out_path) as f:
                result = json.load(f)
        except json.JSONDecodeError:
            result = None
    if result is None:
        try:
            result = json.loads(out.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return {"ok": False, "error": f"no result. stdout: {out[:300]} | stderr: {err[-300:]}"}
    return result


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
