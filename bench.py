"""secure-repl benchmark harness.

Measures the execution substrate end-to-end (bundle + deny-net VM sandbox run):
  - warm latency (sequential, container hot)
  - concurrency sweep -> throughput + p50/p95 wall latency

Run: SECURE_REPL_TOKEN=... <pyenv python> bench.py [--total N] [--levels 1,4,8,16]
"""
import argparse, json, os, statistics, sys, time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))
from secure_repl.client import SecureRepl

SNIPPET = 'import {chunk} from "lodash"; globalThis.__return({n: chunk([1,2,3,4,5,6],2).length});'


def one(repl, i):
    t = time.perf_counter()
    r = repl.eval(SNIPPET, session=f"bench-{i}")
    return {"ms": (time.perf_counter() - t) * 1000, "ok": bool(r.get("ok"))}


def pct(xs, p):
    return round(statistics.quantiles(xs, n=100)[p - 1], 1) if len(xs) > 1 else round(xs[0], 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="1,4,8,16")
    ap.add_argument("--per", type=int, default=8, help="evals per concurrency level")
    args = ap.parse_args()
    repl = SecureRepl()  # $SECURE_REPL_TOKEN

    # Warmup (pay first-call sandbox image build + container spin-up here).
    t = time.perf_counter()
    w = repl.eval(SNIPPET, session="bench-warmup")
    print(f"warmup (cold incl. image build if first): {(time.perf_counter()-t)*1000:.0f} ms ok={w.get('ok')}")

    # Warm sequential latency.
    seq = [one(repl, i)["ms"] for i in range(5)]
    print(f"warm sequential (n=5): p50={pct(seq,50)}ms p95={pct(seq,95)}ms min={min(seq):.0f} max={max(seq):.0f}")

    # Concurrency sweep.
    out = {"warm_seq_ms": seq, "levels": {}}
    for c in [int(x) for x in args.levels.split(",")]:
        lat, t0 = [], time.perf_counter()
        with ThreadPoolExecutor(max_workers=c) as ex:
            for r in ex.map(lambda i: one(repl, i), range(args.per)):
                lat.append(r["ms"])
        wall = time.perf_counter() - t0
        tput = args.per / wall
        rec = {"p50": pct(lat, 50), "p95": pct(lat, 95), "wall_s": round(wall, 2), "throughput_rps": round(tput, 2)}
        out["levels"][c] = rec
        print(f"concurrency={c:>2}: p50={rec['p50']}ms p95={rec['p95']}ms wall={rec['wall_s']}s tput={rec['throughput_rps']}/s")

    print("\nJSON " + json.dumps(out))


if __name__ == "__main__":
    main()
