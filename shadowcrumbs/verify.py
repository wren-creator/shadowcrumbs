"""Verification: does each source's endpoint answer, and does its key work, before you trust a scan to it.

Every check is one cheap request, sent to the service and never to a client:
  * sources check themselves through Plugin.verify(http), next to the code that knows the endpoint and the key
  * the search engine each tier would use is checked here
  * a missing key is reported as missing, with what to set
  * a source that only talks to the client's own systems says so, it is exercised during an authorized run

What it deliberately does not do: send a live query to DuckDuckGo (a test query can trigger the throttle you are
trying to avoid, so it reports the recorded block state instead), or run a billable search to prove a key.
Keys travel in request headers only, and every result passes through log.redact before it is kept.

Results are remembered in data/verify.json so the dashboard can show the last known state of each source.
"""
import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone

from . import config
from .log import logger, redact, safe_url
from .netclient import HttpClient
from .plugin import REGISTRY

STATUSES = ("fail", "warn", "missing", "ok", "unchecked")      # worst first, the order the admin page sorts by
TIMEOUT = 10
LOCK = threading.Lock()
STATE: dict = {"state": "idle", "current": None, "done": 0, "total": 0, "started_at": None}


def _stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _result(check_id, label, tier, status, detail, began, cost=""):
    return {
        "id": check_id, "label": label, "tier": tier, "status": status, "cost": cost,
        "detail": redact(str(detail))[:400], "took_ms": int((time.monotonic() - began) * 1000), "checked_at": _stamp(),
    }


# sources ------------------------------------------------------------------------------------------

def check_source(plugin, http):
    began = time.monotonic()
    cid, tier = f"source:{plugin.name}", plugin.tier
    reason = plugin.unavailable()
    if reason:
        return _result(cid, plugin.name, tier, "missing", reason, began)
    try:
        out = plugin.verify(http)
    except Exception as e:                       # anything that goes wrong talking to the service is a failed check
        return _result(cid, plugin.name, tier, "fail", f"{type(e).__name__}: {e}", began)
    if out is None:
        if plugin.touches_target:
            note = "it talks only to the client's own systems, so it is exercised during an authorized run, not here"
        elif plugin.tier == "search":
            note = "it reads through the search engine, which is checked separately"
        else:
            note = "nothing to check for this source"
        return _result(cid, plugin.name, tier, "unchecked", note, began)
    status, detail = out
    return _result(cid, plugin.name, tier, status if status in STATUSES else "unchecked", detail, began)


# search providers ---------------------------------------------------------------------------------

def check_provider(tier, http):
    """The search engine this tier would use right now. DuckDuckGo is never queried live."""
    began = time.monotonic()
    name = config.search_provider(tier)
    tiers = " and ".join(t for t in ("search", "deep") if config.search_provider(t) == name)
    cid, label = f"provider:{tier}", f"search engine for the {tiers} tier ({name})"
    cost = ""
    try:
        if name == "ddg":
            status, detail = _check_ddg()
        elif name == "brave":
            status, detail, cost = _check_brave(http)
        elif name == "searxng":
            status, detail = _check_searxng(http)
        elif name == "exa":
            status, detail, cost = _check_exa(http)
        elif name == "fixture":
            path = os.environ.get("SHADOWCRUMBS_FIXTURE", "")
            status, detail = ("ok", "canned demo data, no network") if os.path.isfile(path) else ("fail", f"SHADOWCRUMBS_FIXTURE is not a file: {path or '(not set)'}")
        else:
            status, detail = "fail", f"unknown search provider {name!r}"
    except Exception as e:
        status, detail = "fail", f"{type(e).__name__}: {e}"
    rest = config.search_chain(tier)[1:]
    if rest and status in ("ok", "warn"):
        detail += f". If it is throttled, searches move on to: {', '.join(rest)}."
    return _result(cid, label, tier, status, detail, began, cost)


def _check_ddg():
    marker = config.block_marker()
    note = "Not tested live on purpose: a test query is exactly what trips the throttle."
    try:
        at = json.loads(marker.read_text())["at"] if marker.exists() else None
    except (OSError, ValueError, KeyError):
        at = None
    if at:
        left = config.block_minutes() * 60 - (time.time() - at)
        if left > 0:
            return "warn", f"DuckDuckGo blocked this IP {int((time.time() - at) / 60)} minutes ago, searches stay quiet for about {int(left / 60) + 1} more. {note}"
    return "ok", f"no recent block on record. {note}"


def _check_brave(http):
    key = os.environ.get("BRAVE_API_KEY")
    if not key:
        return "missing", "needs BRAVE_API_KEY", ""
    r = http.get("https://api.search.brave.com/res/v1/web/search", params={"q": "example", "count": 1}, timeout=TIMEOUT,
                 headers={"X-Subscription-Token": key, "Accept": "application/json"})
    cost = "uses one search from your Brave quota"
    if r.status_code in (401, 403, 422):
        return "fail", f"Brave rejected the key ({r.status_code}). Check BRAVE_API_KEY.", cost
    if r.status_code == 429:
        return "warn", "Brave rate limited this check (429). The key may be fine, or the quota is used up.", cost
    r.raise_for_status()
    left = r.headers.get("X-RateLimit-Remaining")
    return "ok", "key accepted" + (f", requests left (per second, per month): {left}" if left else ""), cost


def _check_exa(http):
    key = os.environ.get("EXA_API_KEY")
    if not key:
        return "missing", "needs EXA_API_KEY", ""
    r = http.post("https://api.exa.ai/search", json={"query": "example", "numResults": 1}, timeout=TIMEOUT,
                  headers={"x-api-key": key, "Content-Type": "application/json", "Accept": "application/json"})
    cost = "uses one search from your Exa credits"
    if r.status_code in (401, 403):
        return "fail", f"Exa rejected the key ({r.status_code}). Check EXA_API_KEY.", cost
    if r.status_code == 402:
        return "warn", "Exa says the credits are used up (402). The key is accepted, but searches will be refused.", cost
    if r.status_code == 429:
        return "warn", "Exa rate limited this check (429). The key may be fine, or the limit was hit.", cost
    r.raise_for_status()
    return "ok", "key accepted", cost


def _check_searxng(http):
    base = config.searxng_url().rstrip("/")
    where = safe_url(base)
    r = http.get(f"{base}/search", params={"q": "example", "format": "json"}, timeout=TIMEOUT, headers={"Accept": "application/json"})
    if r.status_code == 403:
        return "fail", f"{where} refused the JSON format. Add json under search.formats in its settings.yml."
    if r.status_code == 429:
        return "warn", f"{where} rate limited this check (429)."
    r.raise_for_status()
    data = r.json()
    n, down = len(data.get("results") or []), data.get("unresponsive_engines") or []
    detail = f"{where} answered with {n} results"
    if down:
        detail += f". {len(down)} upstream engine(s) not answering: {', '.join(str(d[0]) if isinstance(d, list) and d else str(d) for d in down[:4])}"
    return ("ok" if n and not down else "warn"), detail


# running ------------------------------------------------------------------------------------------

def plan(only=None):
    """(kind, thing) for everything that will be checked: each distinct search engine, then each source."""
    wanted = set(only or [])
    items, seen = [], set()
    for tier in ("search", "deep"):
        cid = f"provider:{tier}"
        if wanted:
            if cid in wanted:
                items.append(("provider", tier))
        elif config.search_provider(tier) not in seen:         # both tiers on one engine: check it once
            seen.add(config.search_provider(tier))
            items.append(("provider", tier))
    for p in sorted(REGISTRY.values(), key=lambda p: (p.tier != "search", p.order, p.name)):
        if not wanted or f"source:{p.name}" in wanted or p.name in wanted:
            items.append(("source", p))
    return items


def run_checks(only=None, http=None, progress=None):
    """Run the checks now and remember the results. Returns the list of results, worst first."""
    http = http or HttpClient(delay=0.2)
    log = logger().getChild("verify")
    http.log = lambda msg, level="info": log.debug("%s", msg)
    items = plan(only)
    results = []
    for i, (kind, thing) in enumerate(items):
        if progress:
            progress(current=thing if kind == "provider" else thing.name, done=i, total=len(items))
        res = check_provider(thing, http) if kind == "provider" else check_source(thing, http)
        results.append(res)
        _remember([res])                                  # saved as it goes, so the page fills in while a run is going
        log.log(30 if res["status"] in ("fail", "warn") else 20, "%s: %s | %s", res["id"], res["status"], res["detail"])
    if progress:
        progress(current=None, done=len(items), total=len(items))
    return sorted(results, key=lambda r: (STATUSES.index(r["status"]), r["id"]))


def _file():
    return config.data_dir() / "verify.json"


def _remember(results):
    old = last()["checks"]
    old.update({r["id"]: r for r in results})
    path = _file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".verify_", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"checked_at": _stamp(), "checks": old}, f, indent=2)
    os.replace(tmp, path)


def last():
    """The last known result of every check ever run on this machine: {"checked_at": ..., "checks": {id: result}}."""
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        return {"checked_at": data.get("checked_at"), "checks": data.get("checks") or {}}
    except (OSError, ValueError, AttributeError):
        return {"checked_at": None, "checks": {}}


def start(only=None):
    """Run in the background so the page does not hang on a slow service. One run at a time."""
    with LOCK:
        if STATE["state"] == "running":
            raise RuntimeError("a verification is already running")
        STATE.update(state="running", current=None, done=0, total=len(plan(only)), started_at=_stamp(), error=None)

    def progress(**kw):
        with LOCK:
            STATE.update(kw)

    def worker():
        try:
            run_checks(only, progress=progress)
            err = None
        except Exception as e:
            logger().getChild("verify").exception("verification crashed")
            err = redact(f"{type(e).__name__}: {e}")
        with LOCK:
            STATE.update(state="idle", current=None, error=err)

    threading.Thread(target=worker, daemon=True, name="verify").start()


def status():
    with LOCK:
        run = dict(STATE)
    saved = last()
    return {**run, "checked_at": saved["checked_at"],
            "results": sorted(saved["checks"].values(), key=lambda r: (STATUSES.index(r["status"]) if r["status"] in STATUSES else 9, r["id"]))}
