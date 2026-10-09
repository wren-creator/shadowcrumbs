"""Measure how fast DuckDuckGo lets you search before it throttles, from THIS machine and IP.

Sends harmless queries (site:python.org <word>) through the real DuckDuckGoHTML provider at a series of
paces, slowest first, and stops at the first pace that gets blocked. Then it probes now and then (every
10 minutes by default) to see how long the block lasts. Results go to a JSONL log and a summary at the end.

A block shows up two ways: SearchBlocked, or a page that parses to zero results for a query that
always has some (a soft block). Both count.

Usage: python tools/measure_ddg.py [--paces 20,10,5,2.5] [--per-pace 30] [--out FILE]
It deliberately gets your IP throttled for a while. Run it from the network you care about, not one you share.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shadowcrumbs.search import DuckDuckGoHTML, SearchBlocked  # noqa: E402

WORDS = ("python download docs tutorial library module install release about community events jobs "
         "news blog license security pep guide reference history windows mac linux source community "
         "donate success stories shell dictionary string list set tuple class function package").split()
MAX_COOLDOWN_MIN = 180


class Meter:
    def __init__(self, out):
        self.p = DuckDuckGoHTML()
        self.out = open(out, "a", encoding="utf-8")
        self.i = 0
        self.t0 = time.time()

    def query(self, pace):
        word = WORDS[self.i % len(WORDS)]
        self.i += 1
        q = f"site:python.org {word}"
        started = time.time()
        try:
            n = len(self.p.search(q, 10))
            state = "ok" if n else "soft-block"
        except SearchBlocked:
            n, state = 0, "blocked"
        except Exception as e:  # network trouble is not a throttle, record it and keep going
            n, state = 0, f"error:{type(e).__name__}"
        row = {"t": round(started - self.t0, 1), "pace": pace, "q": q, "results": n, "state": state}
        self.out.write(json.dumps(row) + "\n")
        self.out.flush()
        print(f"[{row['t']:7.1f}s] pace={pace:<5} {state:10} results={n}  {q}", flush=True)
        return state


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paces", default="20,10,5,2.5", help="seconds between queries, slowest first")
    ap.add_argument("--per-pace", type=int, default=30)
    ap.add_argument("--probe-minutes", type=float, default=10,
                    help="minutes between probes while blocked. Keep it long, polling a block may extend it")
    ap.add_argument("--out", default="ddg-measure.jsonl")
    a = ap.parse_args()
    m = Meter(a.out)
    summary = {"clean_paces": [], "blocked_pace": None, "queries_before_block": None, "cooldown_minutes": None}

    # Start from a clean slate: if we are already throttled, find out how long it takes to clear.
    if m.query("probe") != "ok":
        print("Already throttled before the test began. Wait an hour or more and try again.", flush=True)
        print("SUMMARY " + json.dumps({"already_blocked": True}), flush=True)
        return

    for pace in (float(x) for x in a.paces.split(",")):
        time.sleep(pace)   # the probe or the last pace counts as a query, so leave a real gap before this pace starts
        sent = 0
        blocked = False
        for _ in range(a.per_pace):
            if m.query(pace) != "ok":
                blocked = True
                break
            sent += 1
            time.sleep(pace)
        if not blocked:
            summary["clean_paces"].append(pace)
            time.sleep(60)   # let any counter drain before the next, faster pace
            continue
        summary["blocked_pace"], summary["queries_before_block"] = pace, sent
        mins = 0.0
        blocked_at = time.time()
        while mins < MAX_COOLDOWN_MIN:
            time.sleep(a.probe_minutes * 60)
            mins = (time.time() - blocked_at) / 60
            if m.query("cooldown") == "ok":
                summary["cooldown_minutes"] = round(mins, 1)
                break
        summary["probes_every_minutes"] = a.probe_minutes
        break
    print("SUMMARY " + json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
