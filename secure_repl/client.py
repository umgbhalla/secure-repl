"""Thin client for the deployed `secure-repl` Modal app (multi-tenant).

Every call carries an API key that maps to a tenant server-side; durable state
is namespaced per tenant, so two tenants using session="s1" never collide.

Usage:
    from secure_repl.client import SecureRepl
    repl = SecureRepl(api_key="...")        # or $SECURE_REPL_TOKEN
    print(repl.eval('import _ from "lodash"; globalThis.__return(_.chunk([1,2,3],2));'))
    repl.eval(PARK_CODE, session="s1")                  # writes /vol/<tenant>/s1/...
    repl.eval(RESUME_CODE, session="s1", resume=True)   # rehydrates that state
"""

import os

import modal


class SecureRepl:
    def __init__(self, api_key: str | None = None, app_name: str | None = None):
        app_name = app_name or os.environ.get("SECURE_REPL_APP", "secure-repl")
        self.api_key = api_key or os.environ.get("SECURE_REPL_TOKEN", "")
        if not self.api_key:
            raise ValueError("api_key required (pass api_key= or set $SECURE_REPL_TOKEN)")
        self._bundle = modal.Function.from_name(app_name, "bundle")
        self._run = modal.Function.from_name(app_name, "run_repl")

    def bundle(self, code: str, allow_hosts: list[str] | None = None) -> dict:
        """Resolve npm + CDN imports into one self-contained ESM blob."""
        return self._bundle.remote(self.api_key, code, allow_hosts)

    def eval(self, code: str, session: str = "default", resume: bool = False,
             persist: bool = False, allow_hosts: list[str] | None = None) -> dict:
        """Bundle `code` then run it in a deny-net VM sandbox.

        `session` namespaces durable state within the caller's tenant. `resume=True`
        rehydrates prior state before running. `persist=True` snapshots state to the
        Volume after running (durable park); off by default for a faster stateless
        eval. The live sandbox is reused per session regardless, so repeat calls to
        the same session skip the microVM cold-start.
        """
        b = self.bundle(code, allow_hosts)
        if not b.get("ok"):
            return {"ok": False, "stage": "bundle", "error": b.get("error")}
        return self._run.remote(
            self.api_key, session, b["code"], "resume" if resume else "fresh", persist
        )
