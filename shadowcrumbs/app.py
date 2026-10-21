"""HTTP API and dashboard. Binds to localhost by default because the data is client confidential."""
from datetime import datetime
from typing import Literal

from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__, config, engine, log
from .exporters import EXPORTERS
from .plugin import LOAD_ERRORS, REGISTRY, describe, load_plugins
from .store import Store, list_slugs

load_plugins()
log.logger().info("Shadowcrumbs %s starting, %d sources loaded, %d failed to load", __version__, len(REGISTRY), len(LOAD_ERRORS))

app = FastAPI(title="Shadowcrumbs", version=__version__, docs_url="/api/docs", openapi_url="/api/openapi.json")


def _host_only(value):
    """Host name from a Host header or an Origin URL, port and brackets stripped."""
    if not value:
        return ""
    value = value.strip().lower()
    host = urlsplit(value if "://" in value else "//" + value).hostname
    return host or ""


@app.middleware("http")
async def only_talk_to_ourselves(request: Request, call_next):
    """Refuse requests that arrive under someone else's name (DNS rebinding) or from another site's page."""
    allowed = config.allowed_hosts()
    if _host_only(request.headers.get("host")) not in allowed:
        return JSONResponse({"detail": "Unknown Host header. Shadowcrumbs only answers on localhost."}, status_code=400)
    origin = request.headers.get("origin")
    if origin and _host_only(origin) not in allowed:
        return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
    return await call_next(request)


class NewEngagement(BaseModel):
    name: str
    company: str | None = None
    domain: str | None = None
    ip: str | None = None
    auth_ref: str | None = None
    authorized: bool = False
    authorized_by: str | None = None     # who is recording the authorization, required when authorized is true


class ScopeUpdate(BaseModel):
    authorized: bool | None = None
    auth_ref: str | None = None
    authorized_by: str | None = None     # required whenever authorized or auth_ref actually changes
    notes: str | None = None


class RunRequest(BaseModel):
    tier: Literal["search", "deep"] = "search"
    plugins: list[str] | None = None


class FindingUpdate(BaseModel):
    notes: str | None = None
    verified: bool | None = None
    confidence: int | None = None


def _store(slug):
    try:
        return Store(slug)
    except KeyError:
        raise HTTPException(404, f"no engagement called {slug!r}") from None


def _summary(slug):
    s = Store(slug)
    return {**s.meta(), "counts": s.counts(), "run": engine.status(slug)}


@app.get("/api/meta")
def meta():
    return {
        "version": __version__,
        "categories": [{"key": k, "label": l} for k, l in config.CATEGORIES],
        "plugins": describe(),
        "plugin_load_errors": dict(LOAD_ERRORS),
    }


@app.get("/api/engagements")
def list_engagements():
    return [_summary(s) for s in list_slugs()]


@app.post("/api/engagements", status_code=201)
def create_engagement(body: NewEngagement):
    try:
        s = Store.create(body.name, body.company, body.domain, body.ip, body.auth_ref, body.authorized,
                     body.authorized_by, require_name=True)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return _summary(s.slug)


@app.get("/api/engagements/{slug}")
def get_engagement(slug: str):
    _store(slug)
    return _summary(slug)


@app.patch("/api/engagements/{slug}")
def update_engagement(slug: str, body: ScopeUpdate):
    s = _store(slug)
    try:
        s.update_meta(body.authorized, body.auth_ref, body.notes, body.authorized_by, require_name=True)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return _summary(slug)


@app.delete("/api/engagements/{slug}", status_code=204)
def delete_engagement(slug: str):
    s = _store(slug)
    if engine.status(slug)["state"] == "running":
        raise HTTPException(409, "a run is in progress")
    history = s.authorizations()
    s.delete_files()
    # the ROE history goes with the database, so keep a line of it in the app log. Only after the delete worked.
    log.logger().info("engagement deleted: %s | ROE history: %s", slug,
                      "; ".join(f"{h['action']} {h['auth_ref']!r} by {h['recorded_by']} at {h['recorded_at'] or 'unknown time'}"
                                for h in history) or "none")
    return Response(status_code=204)


@app.post("/api/engagements/{slug}/runs", status_code=202)
def start_run(slug: str, body: RunRequest):
    _store(slug)
    try:
        return engine.start(slug, body.tier, body.plugins)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from None


@app.get("/api/engagements/{slug}/runs")
def list_runs(slug: str):
    s = _store(slug)
    return {"status": engine.status(slug), "runs": s.runs()}


@app.get("/api/engagements/{slug}/findings")
def list_findings(slug: str, category: str | None = None):
    s = _store(slug)
    if category and category not in config.CATEGORY_KEYS:
        raise HTTPException(400, f"unknown category {category!r}")
    return s.findings(category)


@app.patch("/api/engagements/{slug}/findings/{fid}")
def update_finding(slug: str, fid: int, body: FindingUpdate):
    s = _store(slug)
    try:
        s.update_finding(fid, body.notes, body.verified, body.confidence)
    except KeyError:
        raise HTTPException(404, "no such finding") from None
    return {"ok": True}


@app.delete("/api/engagements/{slug}/findings/{fid}", status_code=204)
def delete_finding(slug: str, fid: int):
    s = _store(slug)
    try:
        s.delete_finding(fid)
    except KeyError:
        raise HTTPException(404, "no such finding") from None
    return Response(status_code=204)


@app.get("/api/engagements/{slug}/authorizations")
def list_authorizations(slug: str):
    return _store(slug).authorizations()


@app.get("/api/engagements/{slug}/events")
def list_events(slug: str, run_id: int | None = None, level: Literal["debug", "info", "warning", "error"] | None = None,
                limit: int = 500):
    return _store(slug).events(run_id, level, limit)


@app.get("/api/admin/roe")
def admin_roe():
    """Every engagement with its full authorization history, for the admin page."""
    out = []
    for slug in list_slugs():
        s = Store(slug)
        m = s.meta()
        out.append({"slug": slug, "name": m["name"], "company": m["company"], "domain": m["domain"], "ip": m["ip"],
                    "authorized": m["authorized"], "auth_ref": m["auth_ref"], "created_at": m["created_at"],
                    "history": s.authorizations()})
    return out


@app.get("/api/admin/logs")
def admin_logs(lines: int = 300, level: Literal["debug", "info", "warning", "error"] | None = None):
    log.logger()          # make sure the handler points at the current data directory before reading
    return {"path": str(log.file_path()), "level": config.log_level(),
            "lines": log.tail(lines, level)}


@app.get("/api/engagements/{slug}/export")
def export(slug: str, format: Literal["md", "json", "pdf"] = "md"):
    s = _store(slug)
    fn, mime, ext = EXPORTERS[format]
    body = fn(s)
    name = f"shadowcrumbs-{slug}-{datetime.now():%Y%m%d}.{ext}"
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})


app.mount("/", StaticFiles(directory=str(config.ROOT / "static"), html=True), name="static")
