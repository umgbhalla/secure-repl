# secure-repl

A cost-effective, configurable **secure-REPL infrastructure** built on top of
[`secure-exec`](https://github.com/umgbhalla/secure-exec). It runs untrusted,
agent-authored REPL code with:

- **npm + CDN package support** — bundle any npm package (via esm.sh) or explicit
  CDN module into one self-contained blob, host-side. No in-guest npm, no network.
- **Secure by default** — code runs in `secure-exec` inside a Modal **VM Sandbox**
  (real Linux kernel) with the default **deny-network** policy. Configurable.
- **Durable park / resume** — per-session filesystem state checkpointed to a
  Modal Volume; resume into a fresh sandbox.

Status: **infra is deployed and validated** (bundle + run + park/resume all green
end-to-end). The ergonomic `SecureRepl` wrapper + hardening items are next — see
`DEPLOYMENT.md` and the gap list below.

## Layout

```
secure_repl/
  app.py                  Modal app: bundle() + run_repl() functions, images, volume
  client.py               SecureRepl thin client (bundle + eval/park/resume)
  assets/
    bundler.mjs           esbuild + http/bare→CDN plugins (host-side, network ok)
    runner.mjs            secure-exec runner (in-sandbox, deny-net, snapshot/restore)
    bundler.package.json  pins esbuild 0.28.1
    runner.package.json   pins secure-exec 0.3.0
DEPLOYMENT.md             topology, why-VM-sandbox, pinned versions, deploy/invoke, cost
```

## Quickstart

```bash
export MODAL_PROFILE=cronus
modal deploy secure_repl/app.py     # deploy
modal run    secure_repl/app.py     # end-to-end smoke test
```

See `DEPLOYMENT.md` for the full operational detail.

## Design choices (locked)

- Untrusted, agent-authored code → deny-net default, configurable policy.
- Density ~10 → one VM sandbox per session, no multi-tenancy gymnastics.
- Packages via a **bundler** (Vite/esbuild-style), not V8 host-mount tricks.
- Persistence on a **Modal Volume**.
- **Idle FS park** (V8 fast path); QuickJS heap-park deferred until proven needed.

## Remaining (post-spike)

1. `SecureRepl` wrapper polish — typed config (policy, allow-hosts, limits),
   `create/eval/park/fork/resume` lifecycle, error taxonomy.
2. Bundle caching by content hash + lockfile pinning (reproducible, supply-chain
   auditable) instead of live-CDN-per-call.
3. Network egress allowlist per session (when a REPL legitimately needs fetch).
4. Snapshot via secure-exec's BARE wire API for full-tree fidelity + COW fork.
5. Addressing/routing layer for parked sessions (id → sandbox) at higher density.
6. CI: deploy + smoke + park/resume on every change.
```
