"""Troubleshooting logs: what a scan did, in words, and proof that no key ever lands in them."""
import logging

import pytest
from fastapi.testclient import TestClient

from shadowcrumbs import config, engine, log
from shadowcrumbs.netclient import HttpClient
from shadowcrumbs.plugin import REGISTRY, Finding, Plugin
from shadowcrumbs.store import Store

FAKE_KEY = "fake-key-for-tests-0123456789"   # nothing like a real key, so no scanner mistakes it for one


@pytest.fixture
def client():
    from shadowcrumbs.app import app
    return TestClient(app)


@pytest.fixture
def tmp_plugin():
    """Register throwaway plugins for one test, then remove them so no other test sees them."""
    added = []

    def add(cls):
        inst = cls()
        REGISTRY[inst.name] = inst
        added.append(inst.name)
        return inst
    yield add
    for n in added:
        REGISTRY.pop(n, None)


def test_redact_masks_every_shape_a_credential_takes(monkeypatch):
    monkeypatch.setenv("ACME_API_KEY", FAKE_KEY)
    samples = [
        f"GET https://x.test/s?q=acme&api_key={FAKE_KEY}&n=2",
        "GET https://x.test/s?access_token=notarealtoken1&q=1",
        "Authorization: Bearer abcdef0123456789abcdef",
        "authorization=Basic dXNlcjpwYXNzd29yZA==",
        "Cookie: session=notarealtoken1",
        "X-Subscription-Token: notarealtoken1",
        "https://user:hunter2@host.test/path",
        f"the key was {FAKE_KEY} in a sentence",
    ]
    for t in samples:
        out = log.redact(t)
        for secret in (FAKE_KEY, "notarealtoken1", "abcdef0123456789abcdef", "hunter2", "dXNlcjpwYXNzd29yZA==", "session=abcdef"):
            assert secret not in out, (t, out)
    assert log.redact("GET https://x.test/s?q=site:acme.test&n=2") == "GET https://x.test/s?q=site:acme.test&n=2"


def test_safe_url_drops_userinfo_fragment_and_secret_values():
    assert log.safe_url("https://u:p@h.test:8443/a?token=zzzzzzzz&q=1#frag") == "https://h.test:8443/a?token=***&q=1"


def test_a_run_leaves_a_readable_trail_in_the_engagement(demo):
    engine.execute(demo.slug, "search", ["emails_search"])
    msgs = [e["message"] for e in demo.events()]
    assert msgs[0].startswith("search tier started") and "emails_search started" in msgs
    assert any(m.startswith("search [fixture]") and "results" in m for m in msgs)
    assert any(m.startswith("emails_search finished: ok") for m in msgs)
    run = demo.runs()[0]
    assert [e["run_id"] for e in demo.events(run_id=run["id"])] == [run["id"]] * len(demo.events(run_id=run["id"]))


def test_a_crash_is_recorded_with_its_traceback_and_the_run_carries_on(demo, tmp_plugin):
    class Boom(Plugin):
        name, tier, order = "boom", "search", 1
        def run(self, ctx):
            ctx.log("about to fail", "warning")
            raise RuntimeError("it broke")
            yield
    tmp_plugin(Boom)
    summary = engine.execute(demo.slug, "search", ["boom", "emails_search"])
    assert [p["status"] for p in summary["plugins"]] == ["error", "ok"]
    errors = demo.events(level="error")
    assert len(errors) == 1 and "RuntimeError: it broke" in errors[0]["message"] and "Traceback" in errors[0]["message"]
    assert any(e["message"] == "about to fail" and e["level"] == "warning" for e in demo.events())


def test_level_filter_is_a_floor(demo):
    demo.add_event(1, "debug", "d"); demo.add_event(1, "info", "i"); demo.add_event(1, "warning", "w"); demo.add_event(1, "error", "e")
    assert [e["message"] for e in demo.events(level="warning")] == ["w", "e"]
    assert [e["message"] for e in demo.events()] == ["d", "i", "w", "e"]


def test_keys_never_reach_events_the_app_log_run_history_or_the_api(demo, tmp_plugin, monkeypatch, client):
    monkeypatch.setenv("LEAKY_API_KEY", FAKE_KEY)

    class Leaky(Plugin):
        name, tier, order = "leaky", "search", 1
        def run(self, ctx):
            ctx.log(f"calling https://api.test/x?api_key={FAKE_KEY}&q=1")
            raise RuntimeError(f"401 for url https://api.test/x?token=notarealtoken1 with key {FAKE_KEY}")
            yield
    tmp_plugin(Leaky)
    engine.execute(demo.slug, "search", ["leaky"])
    everything = [e["message"] for e in demo.events()] + [r["error"] or "" for r in demo.runs()]
    everything += client.get("/api/admin/logs", params={"lines": 500, "level": "debug"}).json()["lines"]
    everything += [e["message"] for e in client.get(f"/api/engagements/{demo.slug}/events").json()]
    assert everything, "nothing was logged, the test would prove nothing"
    blob = "\n".join(everything)
    assert FAKE_KEY not in blob and "notarealtoken1" not in blob
    assert "***" in blob


def test_the_http_client_logs_method_url_status_and_time_but_never_headers_or_bodies(monkeypatch):
    seen = []
    http = HttpClient(delay=0)
    http.log = lambda msg, level="info": seen.append((level, msg))

    class Resp:
        status_code = 200
    monkeypatch.setattr(http.session, "get", lambda url, **kw: Resp())
    http.get("https://api.test/v1?q=1&api_key=" + FAKE_KEY, headers={"X-Api-Key": FAKE_KEY})
    assert len(seen) == 1 and seen[0][0] == "debug"
    assert "GET https://api.test/v1" in seen[0][1] and "-> 200" in seen[0][1] and FAKE_KEY not in seen[0][1]

    class Gone:
        status_code = 503
    monkeypatch.setattr(http.session, "get", lambda url, **kw: Gone())
    http.get("https://api.test/down")
    assert seen[-1][0] == "warning" and "-> 503" in seen[-1][1]

    def explode(url, **kw):
        raise ConnectionError("no route")
    monkeypatch.setattr(http.session, "get", explode)
    with pytest.raises(ConnectionError):
        http.get("https://api.test/dead")
    assert seen[-1][0] == "error" and "ConnectionError" in seen[-1][1]


def test_search_block_is_logged_as_a_warning(demo, monkeypatch):
    from shadowcrumbs.search import SearchBlocked, SearchClient

    class Blocked:
        name = "ddg"
        def search(self, q, n):
            raise SearchBlocked("throttled")
    monkeypatch.setenv("SHADOWCRUMBS_IGNORE_BLOCK", "1")
    seen = []
    sc = SearchClient(Blocked(), demo, delay=0)
    sc.log = lambda msg, level="info": seen.append((level, msg))
    with pytest.raises(SearchBlocked):
        sc.search("site:a.test")
    assert seen[0][0] == "warning" and "BLOCKED" in seen[0][1] and "site:a.test" in seen[0][1]


def test_events_are_pruned_once_per_run_not_per_insert(demo):
    for i in range(30):
        demo.add_event(1, "info", f"line {i}")
    demo.prune_events(keep=10)
    msgs = [e["message"] for e in demo.events(limit=100)]
    assert len(msgs) == 10 and msgs[-1] == "line 29"


def test_events_and_logs_endpoints(client, demo):
    engine.execute(demo.slug, "search", ["emails_search"])
    rows = client.get(f"/api/engagements/{demo.slug}/events", params={"level": "info", "limit": 50}).json()
    assert rows and all(r["level"] != "debug" for r in rows)
    assert client.get(f"/api/engagements/{demo.slug}/events", params={"level": "loud"}).status_code == 422
    logs = client.get("/api/admin/logs", params={"lines": 50}).json()
    assert logs["path"].endswith("shadowcrumbs.log") and any("emails_search finished" in l for l in logs["lines"])
    only_errors = client.get("/api/admin/logs", params={"level": "error"}).json()["lines"]
    assert not any(" INFO " in l for l in only_errors)
    assert client.get("/api/engagements/nope/events").status_code == 404


def test_log_handler_follows_the_data_directory(tmp_path, monkeypatch):
    log.logger().info("first")
    monkeypatch.setenv("SHADOWCRUMBS_DATA", str(tmp_path / "elsewhere"))
    log.logger().info("second")
    assert "second" in (tmp_path / "elsewhere" / "logs" / "shadowcrumbs.log").read_text()
