#!/usr/bin/env python3
"""Make a new data source from the template. Usage:

  python tools/new_plugin.py NAME --tier search --category tech --query 'site:{d} "powered by"'
  python tools/new_plugin.py NAME --tier deep --category infrastructure --key-env MY_API_KEY

It writes plugins_user/NAME.py (or --dir), refuses to overwrite anything, and tells you what to edit next.
{d} in a query is the target domain and {company} is the company name.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shadowcrumbs import config  # noqa: E402
from shadowcrumbs.plugin import REGISTRY, load_plugins  # noqa: E402

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
NEEDS = ("company", "domain", "ip")
BRACES = re.compile(r"\{(?!d\}|company\})|(?<!\{d)(?<!\{company)\}")


def check(name, tier, category, needs, queries, dest_dir):
    """Raise ValueError with a plain reason when the request cannot be turned into a safe plugin file."""
    if not NAME_RE.match(name or ""):
        raise ValueError("name must be lowercase letters, digits and underscores, starting with a letter (2 to 41 characters)")
    if tier not in ("search", "deep"):
        raise ValueError("tier must be search or deep")
    if category not in config.CATEGORY_KEYS:
        raise ValueError(f"category must be one of: {', '.join(config.CATEGORY_KEYS)}")
    bad = [n for n in needs if n not in NEEDS]
    if bad or not needs:
        raise ValueError(f"--needs takes any of: {', '.join(NEEDS)}")
    for q in queries:
        if BRACES.search(q.replace("{d}", "").replace("{company}", "")) or "\n" in q:
            raise ValueError(f"query {q!r}: the only braces allowed are {{d}} and {{company}}, on one line")
    load_plugins()
    if name in REGISTRY:
        raise ValueError(f"a source called {name!r} already exists")
    target = dest_dir / f"{name}.py"
    if target.resolve().parent != dest_dir.resolve():
        raise ValueError("name resolves outside the plugin folder")
    if target.exists():
        raise ValueError(f"{target} already exists, not overwriting it")
    return target


def build(name, tier, category, needs, description, queries, key_env="", touches_target=False):
    """The text of the new plugin file."""
    src = (ROOT / "plugins_user" / f"_template_{tier}.py").read_text(encoding="utf-8")
    cls = "".join(w.capitalize() for w in name.split("_"))
    src = src.replace("__CLASS__", cls).replace("__NAME__", name).replace("__TOUCHES__", str(bool(touches_target)))
    src = src.replace('("__CATEGORY__",)', repr((category,))).replace('"__CATEGORY__"', repr(category))
    src = src.replace('("__NEEDS__",)', repr(tuple(needs)))
    src = src.replace('"__DESCRIPTION__"', repr(description))
    if tier == "search":
        lines = "".join(f"            f{q!r},\n" for q in queries) or "            # f'site:{d} your query here',\n"
        src = src.replace("            # __QUERIES__\n", lines)
    else:
        src = src.replace('KEY_ENV = ""  ', f"KEY_ENV = {key_env!r}  ", 1)
    return src


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make a new Shadowcrumbs data source from the template.")
    ap.add_argument("name", help="snake_case name, shown in the dashboard")
    ap.add_argument("--tier", choices=("search", "deep"), default="search")
    ap.add_argument("--category", required=True, choices=config.CATEGORY_KEYS)
    ap.add_argument("--needs", default="domain", help="comma separated target fields it needs, default domain")
    ap.add_argument("--description", default="")
    ap.add_argument("--query", action="append", default=[], help="search tier: a query, repeat for several")
    ap.add_argument("--key-env", default="", help="deep tier: environment variable that holds the API key")
    ap.add_argument("--touches-target", action="store_true", help="deep tier: it sends traffic to the client")
    ap.add_argument("--dir", default=None, help=f"where to write it, default {config.user_plugins_dir()}")
    a = ap.parse_args(argv)

    dest = Path(a.dir).expanduser() if a.dir else config.user_plugins_dir()
    needs = [n.strip() for n in a.needs.split(",") if n.strip()]
    description = a.description or "TODO: one line on what this source finds."
    try:
        if a.key_env and not re.match(r"^[A-Z][A-Z0-9_]{2,60}$", a.key_env):
            raise ValueError("--key-env must look like MY_API_KEY")
        target = check(a.name, a.tier, a.category, needs, a.query, dest)
        text = build(a.name, a.tier, a.category, needs, description, a.query, a.key_env, a.touches_target)
        compile(text, str(target), "exec")           # never write a file that does not even parse
    except ValueError as e:
        print(f"Not created: {e}", file=sys.stderr)
        return 1
    dest.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(f"Created {target}")
    print("Next:")
    if a.tier == "search":
        print("  1. Edit the queries, the filter, and what gets recorded (the three numbered comments in the file).")
    else:
        print("  1. Set URL, check the key header name, and map the response into Findings (the three numbered comments).")
        print("     It shows as skipped until URL is filled in.")
    print("  2. Restart (./shadowcrumbs.sh restart). It appears in the dashboard under its tier.")
    print("  3. Try it on ./shadowcrumbs.sh start --demo first. Add a test: tests/test_deep.py shows the pattern with a fake http object.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
