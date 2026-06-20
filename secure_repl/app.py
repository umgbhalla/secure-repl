"""secure-repl infra — production Modal app.

Two-stage pipeline for running untrusted, agent-authored REPL code with npm/CDN
package support and durable park/resume:

  bundle()   network-allowed Modal Function. Resolves npm + allowlisted-CDN
             imports into one self-contained ESM blob (esbuild). Output carries
             zero unresolved imports, so the runner needs neither npm nor net.

  run_repl() VM Sandbox (real Linux kernel, required for secure-exec's sidecar
             openat2/namespace primitives) with a DENY-NET permission policy.
             Loads the blob into secure-exec, runs it, and parks/resumes session
             state through a mounted Modal Volume.

Deploy:   modal deploy secure_repl/app.py
Invoke:   see secure_repl/client.py / README.md

Pinned: Modal SDK 1.5.x, node 22, esbuild 0.28.1, secure-exec 0.3.0.
"""

import json
from pathlib import Path

import modal

APP_NAME = "secure-repl"
ASSETS = Path(__file__).parent / "assets"

app = modal.App(APP_NAME)

# Durable session state (park/resume manifests live here as /<session>/fs.json).
state_volume = modal.Volume.from_name("secure-repl-state", create_if_missing=True)

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

# Resource + safety defaults (density target ~10 concurrent sessions).
RUNNER_CPU = 2
RUNNER_MEM_MB = 2048
RUNNER_TIMEOUT_S = 300


@app.function(image=bundler_image, timeout=120, max_containers=10)
def bundle(entry: str, allow_hosts: list[str] | None = None) -> dict:
    """Resolve npm + CDN imports in `entry` into one self-contained ESM blob.

    Returns {ok, bytes, ms, code} | {ok: False, error}. Runs network-allowed.
    """
    import subprocess

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


@app.function(image=runner_image, timeout=RUNNER_TIMEOUT_S + 60, volumes={"/vol": state_volume})
def run_repl(session_id: str, bundle_code: str, mode: str = "fresh") -> dict:
    """Run a bundle inside a deny-net VM Sandbox with park/resume via Volume.

    `mode`: "fresh" (ignore prior state) | "resume" (rehydrate /vol/<session>).
    Returns the runner contract dict (value, saved, rehydrated, ...).
    """
    import os

    state_dir = f"/vol/{session_id}"
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
        image=runner_image,
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
    """Smoke test: bundle a tiny npm+CDN snippet and run it end-to-end."""
    if not code:
        code = (
            'import { chunk } from "lodash";\n'
            'import pluralize from "https://esm.sh/pluralize";\n'
            'globalThis.__return({ grouped: chunk([1,2,3,4,5],2), plural: pluralize("repl",3,true) });'
        )
    b = bundle.remote(code)
    assert b.get("ok"), f"bundle failed: {b}"
    print(f"bundled: {b['bytes']} bytes in {b['ms']}ms")
    r = run_repl.remote(session, b["code"], mode)
    print("run_repl:", json.dumps(r, indent=2))
