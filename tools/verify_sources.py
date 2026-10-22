#!/usr/bin/env python3
"""Check every source's endpoint and key from the command line. Usage:

  python tools/verify_sources.py                 # everything
  python tools/verify_sources.py hibp_breaches   # just that source (or provider:search, provider:deep)
  python tools/verify_sources.py --json          # machine readable
  python tools/verify_sources.py --strict        # a missing key or a warning also fails

Exit code 1 when a check fails, so it can sit in front of an engagement as a preflight. Requests go to the services
themselves and ask about example.com, never a client. Keys are read from the environment, like the app does.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shadowcrumbs import custom_sources, verify  # noqa: E402
from shadowcrumbs.plugin import load_plugins  # noqa: E402

MARK = {"ok": "OK     ", "fail": "FAIL   ", "warn": "WARN   ", "missing": "MISSING", "unchecked": "-      "}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify Shadowcrumbs sources: endpoints and API keys.")
    ap.add_argument("only", nargs="*", help="source names, or provider:search / provider:deep. Default: everything")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="fail on warnings and missing keys too")
    a = ap.parse_args(argv)

    load_plugins()
    custom_sources.sync()
    results = verify.run_checks(a.only or None)
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            cost = f"  [{r['cost']}]" if r["cost"] else ""
            print(f"{MARK[r['status']]} {r['label']}: {r['detail']}{cost}")
        counts = {s: sum(r["status"] == s for r in results) for s in verify.STATUSES}
        print("\n" + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    bad = {"fail", "warn", "missing"} if a.strict else {"fail"}
    return 1 if any(r["status"] in bad for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
