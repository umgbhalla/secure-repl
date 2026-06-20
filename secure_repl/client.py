"""Thin client for the deployed `secure-repl` Modal app.

Usage:
    from secure_repl.client import SecureRepl
    repl = SecureRepl()
    print(repl.eval('import _ from "lodash"; globalThis.__return(_.chunk([1,2,3],2));'))
    repl.eval(PARK_CODE, session="s1")              # writes /home/user/state/...
    repl.eval(RESUME_CODE, session="s1", resume=True)  # rehydrates that state
"""

import modal


class SecureRepl:
    def __init__(self, app_name: str = "secure-repl"):
        self._bundle = modal.Function.from_name(app_name, "bundle")
        self._run = modal.Function.from_name(app_name, "run_repl")

    def bundle(self, code: str, allow_hosts: list[str] | None = None) -> dict:
        """Resolve npm + CDN imports into one self-contained ESM blob."""
        return self._bundle.remote(code, allow_hosts)

    def eval(self, code: str, session: str = "default", resume: bool = False,
             allow_hosts: list[str] | None = None) -> dict:
        """Bundle `code` then run it in a deny-net VM sandbox.

        `session` namespaces durable state on the Volume. `resume=True`
        rehydrates prior state before running.
        """
        b = self.bundle(code, allow_hosts)
        if not b.get("ok"):
            return {"ok": False, "stage": "bundle", "error": b.get("error")}
        return self._run.remote(session, b["code"], "resume" if resume else "fresh")
