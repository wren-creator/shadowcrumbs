"""Runs plugins against an engagement and records what happened."""
import threading
import time
import traceback

from . import config
from .log import logger, redact
from .netclient import HttpClient
from .plugin import REGISTRY, Context
from .search import SearchClient, make_chain
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


def resolve_domains(meta, domains=None):
    """The domains a run covers. None means the engagement's own domain. Anything else must be that domain or one
    of the subdomains pulled into scope: a run never goes to a host the operator did not put in scope."""
    allowed = [meta["domain"], *(d["domain"] for d in meta["scope_domains"])]
    if not domains:
        return [meta["domain"]]
    out = []
    for d in domains:
        d = (d or "").strip().lower()
        if d not in allowed:
            raise ValueError(f"{d!r} is not in scope for this engagement")
        if d not in out:
            out.append(d)
    return out


def execute(slug, tier, names=None, progress=None, domains=None):
    """Run the selected plugins one after another, once per domain in play. Returns a summary dict."""
    store = Store(slug)
    _check_gate(store, tier)
    plugins = select(tier, names)
    meta = store.meta()
    domains = resolve_domains(meta, domains)
    target = {k: meta[k] for k in ("company", "domain", "ip")}
    search = SearchClient(make_chain(tier), store)
    ctx = Context(target=target, search=search, http=HttpClient(), store=store)
    app_log = logger()
    levels = {"debug": 10, "info": 20, "warning": 30, "error": 40}

    def emitter(run_id):
        """One function that writes to this run's events and to the app log. Plugins, the search client and the
        HTTP client all get it, so a problem shows up in both places with the same words."""
        def emit(msg, level="info"):
            store.add_event(run_id, level, msg)
            app_log.log(levels.get(level, 20), "[%s #%s] %s", slug, run_id, msg)
        return emit

    summary = {"tier": tier, "plugins": [], "new_findings": 0}
    first = True
    jobs = [(d, p) for d in domains for p in plugins]
    for i, (d, p) in enumerate(jobs):
        target = ctx.target = {**target, "domain": d}
        label = p.name if d == meta["domain"] else f"{p.name} @ {d}"     # keeps a subdomain run from hiding the main one in the history
        if progress:
            progress(current=label, done=i, total=len(jobs))
        run_id = store.start_run(label, p.tier)
        emit = ctx.log = search.log = ctx.http.log = emitter(run_id)
        if first:
            emit(f"{tier} tier started: {len(plugins)} source(s) x {len(domains)} domain(s), search engines "
                 f"{' > '.join(p.name for p in search.chain)}, target {', '.join(f'{k}={v}' for k, v in target.items() if v)}")
            first = False
        emit(f"{label} started")
        began = time.monotonic()
        found, status, err, trace = 0, "ok", None, ""
        if not p.applicable(target):
            status, err = "skipped", "needs " + p.needs_text()
        elif p.unavailable():
            status, err = "skipped", p.unavailable()
        else:
            try:
                for f in p.run(ctx):
                    if store.add_finding(f.category, f.value, p.name, p.tier, f.url, f.confidence, f.notes):
                        found += 1
            except Exception as e:  # one bad source must not stop the rest
                status, err = ("partial" if found else "error"), f"{type(e).__name__}: {e}"
                trace = "\n" + traceback.format_exc(limit=8)
        err = redact(err) if err else err
        store.finish_run(run_id, status, found, err)
        emit(f"{label} finished: {status}, {found} new, {time.monotonic() - began:.1f}s" + (f" | {err}" if err else "") + trace,
             "warning" if status in ("skipped", "partial") else "error" if status == "error" else "info")
        summary["plugins"].append({"name": label, "status": status, "found": found, "error": err})
        summary["new_findings"] += found
    if progress:
        progress(current=None, done=len(jobs), total=len(jobs))
    summary["searches_live"] = search.live_queries
    summary["searches_cached"] = search.cached_queries
    summary["search_blocked"] = search.blocked
    store.prune_events()
    app_log.info("[%s] %s tier finished: %s new, %s live searches, %s cached%s", slug, tier, summary["new_findings"],
                 search.live_queries, search.cached_queries, ", search engine blocked" if search.blocked else "")
    return summary


def start(slug, tier, names=None, domains=None):
    """Kick off a run in the background. One run per engagement at a time."""
    store = Store(slug)
    _check_gate(store, tier)
    plugins = select(tier, names)
    domains = resolve_domains(store.meta(), domains)
    with LOCK:
        cur = STATE.get(slug)
        if cur and cur["state"] == "running":
            raise RuntimeError("a run is already in progress for this engagement")
        STATE[slug] = {
            "state": "running", "tier": tier, "total": len(plugins) * len(domains), "done": 0,
            "current": None, "started_at": now(), "summary": None, "error": None,
        }

    def progress(**kw):
        with LOCK:
            STATE[slug].update(kw)

    def worker():
        try:
            summary = execute(slug, tier, names, progress, domains)
            with LOCK:
                STATE[slug].update(state="idle", summary=summary, current=None)
        except Exception as e:
            logger().exception("[%s] %s run crashed", slug, tier)
            with LOCK:
                STATE[slug].update(state="idle", error=redact(f"{type(e).__name__}: {e}"), current=None)

    threading.Thread(target=worker, daemon=True, name=f"run-{slug}").start()
    return status(slug)


def status(slug):
    with LOCK:
        return dict(STATE.get(slug) or {"state": "idle", "summary": None, "error": None})
