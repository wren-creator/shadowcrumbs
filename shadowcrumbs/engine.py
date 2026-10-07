"""Runs plugins against an engagement and records what happened."""
import threading

from . import config
from .netclient import HttpClient
from .plugin import REGISTRY, Context
from .search import SearchClient, make_provider
from .store import Store, now

STATE: dict = {}
LOCK = threading.Lock()


def select(tier, names=None):
    if tier not in ("search", "deep"):
        raise ValueError("tier must be 'search' or 'deep'")
    pool = {n: p for n, p in REGISTRY.items() if p.tier == tier}
    if names:
        unknown = [n for n in names if n not in pool]
        if unknown:
            raise ValueError(f"unknown {tier} plugin(s): {', '.join(unknown)}")
        pool = {n: pool[n] for n in names}
    return sorted(pool.values(), key=lambda p: (p.order, p.name))


def _check_gate(store, tier):
    if tier == "deep" and not store.meta()["authorized"]:
        raise PermissionError(
            "Deep dive is locked. Record the authorization reference for this engagement first."
        )


def execute(slug, tier, names=None, progress=None):
    """Run the selected plugins one after another. Returns a summary dict."""
    store = Store(slug)
    _check_gate(store, tier)
    plugins = select(tier, names)
    meta = store.meta()
    target = {k: meta[k] for k in ("company", "domain", "ip")}
    search = SearchClient(make_provider(tier), store)
    ctx = Context(target=target, search=search, http=HttpClient(), store=store)

    summary = {"tier": tier, "plugins": [], "new_findings": 0}
    for i, p in enumerate(plugins):
        if progress:
            progress(current=p.name, done=i, total=len(plugins))
        run_id = store.start_run(p.name, p.tier)
        found, status, err = 0, "ok", None
        if not p.applicable(target):
            status, err = "skipped", "needs " + " or ".join(p.needs_any)
        else:
            try:
                for f in p.run(ctx):
                    if store.add_finding(f.category, f.value, p.name, p.tier, f.url, f.confidence, f.notes):
                        found += 1
            except Exception as e:  # one bad source must not stop the rest
                status, err = ("partial" if found else "error"), f"{type(e).__name__}: {e}"
        store.finish_run(run_id, status, found, err)
        summary["plugins"].append({"name": p.name, "status": status, "found": found, "error": err})
        summary["new_findings"] += found
    if progress:
        progress(current=None, done=len(plugins), total=len(plugins))
    summary["searches_live"] = search.live_queries
    summary["searches_cached"] = search.cached_queries
    summary["throttle_waits"] = search.throttle_waits
    return summary


def start(slug, tier, names=None):
    """Kick off a run in the background. One run per engagement at a time."""
    store = Store(slug)
    _check_gate(store, tier)
    plugins = select(tier, names)
    with LOCK:
        cur = STATE.get(slug)
        if cur and cur["state"] == "running":
            raise RuntimeError("a run is already in progress for this engagement")
        STATE[slug] = {
            "state": "running", "tier": tier, "total": len(plugins), "done": 0,
            "current": None, "started_at": now(), "summary": None, "error": None,
        }

    def progress(**kw):
        with LOCK:
            STATE[slug].update(kw)

    def worker():
        try:
            summary = execute(slug, tier, names, progress)
            with LOCK:
                STATE[slug].update(state="idle", summary=summary, current=None)
        except Exception as e:
            with LOCK:
                STATE[slug].update(state="idle", error=f"{type(e).__name__}: {e}", current=None)

    threading.Thread(target=worker, daemon=True, name=f"run-{slug}").start()
    return status(slug)


def status(slug):
    with LOCK:
        return dict(STATE.get(slug) or {"state": "idle", "summary": None, "error": None})
