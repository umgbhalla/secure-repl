# Deployment & Infra — secure-repl

Production deployment details for the secure-repl infra (a cost-effective,
configurable secure-REPL layer built on top of [`secure-exec`](https://github.com/umgbhalla/secure-exec),
with npm/CDN package bundling and durable park/resume).

## Topology

```
agent code ──▶ bundle()  ──────────────▶  run_repl()  ──────────▶ result
              [Modal Function]            [Modal Function]
              node:22-slim                node:22 (full)
              esbuild + http plugin       spawns a VM Sandbox:
              npm+CDN → 1 ESM blob          - experimental vm_runtime=True
              NETWORK ALLOWED               - secure-exec, DENY-NET default
                                            - Modal Volume mounted at /vol
                                            - park/resume via /vol/<session>/
```

Two stages, deliberately split by trust + network posture:

- **bundle()** runs network-allowed (it must fetch npm + CDN). Its output blob
  carries zero unresolved imports, so the runner needs neither npm nor network.
- **run_repl()** spawns a **VM Sandbox** (real Linux kernel — required; see
  below) running `secure-exec` with its default **deny-network** policy. Agent
  code is untrusted; the only way out is the blob we handed it.

## Why a VM Sandbox (not a normal/gVisor sandbox)

`secure-exec`'s sidecar uses `openat2` (+ `RESOLVE_BENEATH`, `O_PATH`) for safe
path resolution. gVisor (Modal's default sandbox) caps at a ~4.19 syscall
surface and returns `ENOSYS` for `openat2` (kernel ≥5.6). Probed empirically:

| runtime            | kernel        | openat2 | verdict                |
|--------------------|---------------|---------|------------------------|
| normal (gVisor)    | 4.19.0-gvisor | ENOSYS  | sidecar cannot run     |
| VM (`vm_runtime`)  | 6.12.8 real   | works   | required, works        |

So `experimental_options={"vm_runtime": True}` is mandatory for the runner.

## Pinned versions

| component   | version | where                                   |
|-------------|---------|-----------------------------------------|
| Modal SDK   | 1.5.x   | local + CI                              |
| node        | 22      | both images                             |
| esbuild     | 0.28.1  | `assets/bundler.package.json`           |
| secure-exec | 0.3.0   | `assets/runner.package.json`            |

Runner image MUST be full `node:22`, NOT `node:22-slim`: the native Rust sidecar
binary needs shared libs the slim image omits; missing them makes the sidecar
child exit on startup, surfacing as `EPIPE` on the stdio frame transport.

## Resources & cost

Runner sandbox defaults: `cpu=2, memory=2048MiB, timeout=300s` (density target
~10 concurrent sessions). Modal Sandbox rates: ~$0.142/core/hr + ~$0.0242/GiB/hr,
billed per-second. A 2c/2GiB session ≈ $0.33/hr; a typical sub-minute REPL run is
fractions of a cent. The Starter plan's $30/mo free credit covers a lot of runs.

## Deploy

```bash
export MODAL_PROFILE=cronus
modal deploy secure_repl/app.py
```

Creates/updates the `secure-repl` app with functions `bundle` and `run_repl`,
plus the `secure-repl-state` Volume (auto-created). Images are content-addressed
and cached, so redeploys after asset-only edits are fast.

## Invoke

End-to-end smoke test (bundles a tiny npm+CDN snippet and runs it):

```bash
modal run secure_repl/app.py
```

From other Python (looked-up, no redeploy):

```python
import modal
bundle   = modal.Function.from_name("secure-repl", "bundle")
run_repl = modal.Function.from_name("secure-repl", "run_repl")

b = bundle.remote('import _ from "lodash"; globalThis.__return(_.chunk([1,2,3],2));')
r = run_repl.remote("my-session", b["code"], "fresh")   # or "resume"
```

See `secure_repl/client.py` for a thin wrapper.

## Package model

The bundler is **stateless** — no per-session `node_modules`. Resolution:

- relative/absolute imports → esbuild
- explicit `https://` imports → fetched (allowlisted hosts only)
- bare specifiers (`lodash`, `@scope/pkg`) → rewritten to `https://esm.sh/<spec>`
  (esm.sh is the npm→ESM bridge), so "npm or cdnjs" is one path.
- `node:` builtins → external (provided by the secure-exec runtime)

CDN allowlist (SSRF/supply-chain guard): esm.sh, jsdelivr, cdnjs, unpkg, esm.run.
Extend per-call via `allow_hosts`.

## Park / resume

State lives under `GUEST_STATE=/home/user/state` in the guest. The runner
snapshots that subtree to a `{path: base64}` manifest at
`/vol/<session>/fs.json` on the mounted Volume. `mode="resume"` rehydrates it
into a fresh sandbox before running. State crosses sandboxes only through the
Volume — nothing in-process is shared.

> Park depth note: this is **idle filesystem park** (V8 fast path). True
> mid-`await` heap park (continuation capture) is intentionally deferred — V8
> cannot serialize a live isolate heap; that would need a QuickJS engine swap.
> For agent-authored REPLs that checkpoint to disk, FS-park is sufficient.

## Operational notes

- `state_volume.commit()` after staging input + after a run; `reload()` before
  reading the result file. Stdin to a VM Sandbox is unreliable, so I/O goes
  through Volume files (`INPUT_FILE`/`OUTPUT_FILE` env), with a stdout echo.
- A late `EPIPE` from sidecar teardown is swallowed once the result is written.
- 8GB-class hosts OOM at the V8 link step if you ever build secure-exec from
  source here; we install the prebuilt npm package, so this only matters for the
  upstream repo's own test builds (use ≥16GB + `CARGO_PROFILE_TEST_DEBUG=0`).
