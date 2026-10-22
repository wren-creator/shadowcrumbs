"""Verification: endpoints and keys are checked with one harmless request each, and nothing leaks or reaches a client."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from shadowcrumbs import config, verify
from shadowcrumbs.plugin import REGISTRY, load_plugins
from shadowcrumbs.plugins import credential_plugins, deep_plugins

KEY = "fake-key-for-tests-9876543210"


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body if body is not None else {}, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    """Answers by URL fragment, records every call so tests can see exactly what would have gone out."""

    def __init__(self, routes=None, default=None):
        self.routes, self.default, self.calls = routes or {}, default or Resp(200, {}), []
        self.log = lambda msg, level="info": None

    def _answer(self, method, url, kw):
        self.calls.append((method, url, kw))
        for frag, ans in self.routes.items():
            if frag in url:
                if isinstance(ans, Exception):
                    raise ans
                return ans
        return self.default

    def get(self, url, timeout=None, **kw):
        return self._answer("GET", url, kw)

    def head(self, url, timeout=None, **kw):
        return self._answer("HEAD", url, kw)

    def get_json(self, url, timeout=None):
        r = self._answer("GET", url, {})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


@pytest.fixture(autouse=True)
def registry():
    load_plugins()
    yield
    for n in [n for n, p in list(REGISTRY.items()) if p.custom]:
        REGISTRY.pop(n)


@pytest.fixture(autouse=True)
def no_keys(monkeypatch):
    for k in ("HIBP_API_KEY", "DEHASHED_API_KEY", "GITHUB_TOKEN", "URLSCAN_API_KEY", "BRAVE_API_KEY",
              "SHADOWCRUMBS_BREACH_FILE", "SHADOWCRUMBS_SEARXNG_URL"):
        monkeypatch.delenv(k, raising=False)


def check(name, http):
    return verify.check_source(REGISTRY[name], http)


# sources ------------------------------------------------------------------------------------------

def test_a_missing_key_is_missing_not_failed_and_no_request_is_sent():
    http = FakeHttp()
    r = check("hibp_breaches", http)
    assert (r["status"], r["detail"]) == ("missing", "needs HIBP_API_KEY") and http.calls == []


def test_hibp_key_states(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", KEY)
    ok = check("hibp_breaches", FakeHttp({"subscription/status": Resp(200, {"SubscriptionName": "Pwned 1"})}))
    assert ok["status"] == "ok" and "key accepted, plan: Pwned 1" == ok["detail"]
    assert check("hibp_breaches", FakeHttp({"subscription/status": Resp(401)}))["status"] == "fail"
    assert check("hibp_breaches", FakeHttp({"subscription/status": Resp(429)}))["status"] == "warn"
    assert check("hibp_breaches", FakeHttp({"subscription/status": Resp(404)}))["status"] == "warn"
    down = check("hibp_breaches", FakeHttp({"subscription/status": ConnectionError("no route to host")}))
    assert down["status"] == "fail" and "ConnectionError" in down["detail"]


def test_hibp_check_sends_the_key_in_a_header_and_looks_up_no_address(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", KEY)
    http = FakeHttp()
    check("hibp_breaches", http)
    [(method, url, kw)] = http.calls
    assert url == "https://haveibeenpwned.com/api/v3/subscription/status" and KEY not in url
    assert kw["headers"]["hibp-api-key"] == KEY


def test_github_token_states_and_the_private_repo_warning(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", KEY)
    body = {"resources": {"code_search": {"remaining": 9}}}
    fine = check("github_code_search", FakeHttp({"rate_limit": Resp(200, body)}))             # fine-grained tokens send no scopes
    assert fine["status"] == "ok" and "9 code searches left" in fine["detail"]
    classic = check("github_code_search", FakeHttp({"rate_limit": Resp(200, body, {"X-OAuth-Scopes": "read:org, repo"})}))
    assert classic["status"] == "warn" and "private code" in classic["detail"] and "fine-grained" in classic["detail"]
    narrow = check("github_code_search", FakeHttp({"rate_limit": Resp(200, body, {"X-OAuth-Scopes": "public_repo"})}))
    assert narrow["status"] == "ok"
    assert check("github_code_search", FakeHttp({"rate_limit": Resp(401)}))["status"] == "fail"


def test_urlscan_works_without_a_key_and_catches_a_bad_one(monkeypatch):
    assert check("urlscan_search", FakeHttp())["detail"] == "reachable, no key set so the free limits apply"
    anon = check("urlscan_search", FakeHttp({"urlscan.io": Resp(403)}))
    assert anon["status"] == "fail" and "anonymous" in anon["detail"]
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    http = FakeHttp({"urlscan.io": Resp(401)})
    bad = check("urlscan_search", http)
    assert bad["status"] == "fail" and "URLSCAN_API_KEY" in bad["detail"] and http.calls[0][2]["headers"]["API-Key"] == KEY
    assert check("urlscan_search", FakeHttp())["detail"] == "key accepted"


def test_public_sources_rdap_crtsh_wayback_and_dns(monkeypatch):
    from pathlib import Path
    monkeypatch.setenv("SHADOWCRUMBS_PLUGINS", str(Path(__file__).resolve().parent.parent / "plugins_user"))
    load_plugins()                                      # the example plugin that ships in plugins_user/
    assert "wayback_urls" in REGISTRY
    assert check("rdap", FakeHttp({"rdap.org": Resp(200, {"ldhName": "EXAMPLE.COM"})}))["status"] == "ok"
    assert check("rdap", FakeHttp({"rdap.org": Resp(404)}))["status"] == "warn"
    assert check("rdap", FakeHttp({"rdap.org": Resp(500)}))["status"] == "fail"
    assert check("crtsh", FakeHttp({"crt.sh": Resp(200)}))["status"] == "ok"
    assert check("crtsh", FakeHttp({"crt.sh": Resp(503)}))["status"] == "warn"
    assert check("wayback_urls", FakeHttp({"web.archive.org": Resp(200, [["original"], ["http://example.com/"]])}))["status"] == "ok"
    monkeypatch.setattr(deep_plugins, "dns_lookup", lambda name, rtype: (["93.184.216.34"], "ok"))
    assert check("dns_records", FakeHttp())["status"] == "ok" and check("resolve_subdomains", FakeHttp())["status"] == "ok"
    monkeypatch.setattr(deep_plugins, "dns_lookup", lambda name, rtype: ([], "error"))
    assert check("dns_records", FakeHttp())["status"] == "fail"
    REGISTRY.pop("wayback_urls", None)


def test_dehashed_key_states(monkeypatch):
    monkeypatch.setenv("DEHASHED_API_KEY", KEY)
    route = "v2/info/user"
    ok = check("dehashed_domain", FakeHttp({route: Resp(200, {"search_access": True, "search_credits": 500})}))
    assert ok["status"] == "ok" and "500" in ok["detail"]
    nosub = check("dehashed_domain", FakeHttp({route: Resp(200, {"search_access": False, "search_credits": 500})}))
    assert nosub["status"] == "fail" and "subscription" in nosub["detail"]
    assert check("dehashed_domain", FakeHttp({route: Resp(200, {"search_access": True, "search_credits": 0})}))["status"] == "warn"
    bad = check("dehashed_domain", FakeHttp({route: Resp(401, {"error": "issue with authentication"})}))
    assert bad["status"] == "fail" and "issue with authentication" in bad["detail"]
    assert check("dehashed_domain", FakeHttp({route: Resp(429)}))["status"] == "warn"


def test_dehashed_check_is_a_get_with_the_key_in_a_header_and_never_a_search(monkeypatch):
    monkeypatch.setenv("DEHASHED_API_KEY", KEY)
    http = FakeHttp({"v2/info/user": Resp(200, {"search_access": True, "search_credits": 1})})
    r = check("dehashed_domain", http)
    assert [(m, u.split("/v2/")[1]) for m, u, _ in http.calls] == [("GET", "info/user")]
    assert http.calls[0][2]["headers"]["Dehashed-Api-Key"] == KEY and KEY not in json.dumps(r)


def test_breach_file_is_checked_for_existence_and_readability(tmp_path, monkeypatch):
    f = tmp_path / "feed.csv"
    f.write_text("email,password\n")
    monkeypatch.setenv("SHADOWCRUMBS_BREACH_FILE", str(f))
    assert check("breach_file_import", FakeHttp())["status"] == "ok"
    monkeypatch.setenv("SHADOWCRUMBS_BREACH_FILE", str(tmp_path / "gone.csv"))
    r = check("breach_file_import", FakeHttp())
    assert r["status"] == "missing" and "not a file" in r["detail"]


def test_sources_that_only_talk_to_the_client_are_not_pinged():
    http = FakeHttp()
    for name in ("http_probe", "doc_metadata"):
        r = check(name, http)
        assert r["status"] == "unchecked" and "client's own systems" in r["detail"]
    assert http.calls == []


def test_search_sources_point_at_the_search_engine_check():
    r = check("emails_search", FakeHttp())
    assert r["status"] == "unchecked" and "search engine" in r["detail"]


def test_a_custom_source_checks_its_definition(monkeypatch):
    from shadowcrumbs import custom_sources as cs
    cs.create({"label": "Mine", "category": "tech", "needs": ["domain"], "queries": ["site:{domain}"], "author": "Pat"})
    r = check("custom_mine", FakeHttp())
    assert r["status"] == "ok" and "1 search" in r["detail"]


# search engines -----------------------------------------------------------------------------------

def test_duckduckgo_is_never_queried_live_and_reports_the_recorded_block(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: pytest.fail("a live DuckDuckGo query would risk the throttle"))
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("no network for DuckDuckGo"))
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH", "ddg")
    http = FakeHttp()
    r = verify.check_provider("search", http)
    assert r["status"] == "ok" and "Not tested live on purpose" in r["detail"] and http.calls == []
    marker = config.block_marker()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"at": time.time() - 600}))
    blocked = verify.check_provider("search", http)
    assert blocked["status"] == "warn" and "blocked this IP 10 minutes ago" in blocked["detail"] and http.calls == []


def test_brave_key_check_and_its_cost(monkeypatch):
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH", "brave")
    assert verify.check_provider("deep", FakeHttp())["status"] == "missing"
    monkeypatch.setenv("BRAVE_API_KEY", KEY)
    http = FakeHttp({"brave.com": Resp(200, {}, {"X-RateLimit-Remaining": "1, 1999"})})
    r = verify.check_provider("deep", http)
    assert r["status"] == "ok" and "1, 1999" in r["detail"] and r["cost"] == "uses one search from your Brave quota"
    assert http.calls[0][2]["headers"]["X-Subscription-Token"] == KEY and KEY not in http.calls[0][1]
    assert verify.check_provider("deep", FakeHttp({"brave.com": Resp(401)}))["status"] == "fail"
    assert verify.check_provider("deep", FakeHttp({"brave.com": Resp(429)}))["status"] == "warn"


def test_searxng_json_and_unresponsive_engines(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH")                   # the test environment forces the fixture provider
    monkeypatch.setenv("SHADOWCRUMBS_SEARXNG_URL", "http://user:pw@127.0.0.1:8888/")
    good = verify.check_provider("search", FakeHttp({"/search": Resp(200, {"results": [{}] * 10})}))
    assert good["status"] == "ok" and "10 results" in good["detail"] and "pw" not in good["detail"]
    thin = verify.check_provider("search", FakeHttp({"/search": Resp(200, {"results": [{}], "unresponsive_engines": [["duckduckgo", "CAPTCHA"]]})}))
    assert thin["status"] == "warn" and "duckduckgo" in thin["detail"]
    nojson = verify.check_provider("search", FakeHttp({"/search": Resp(403)}))
    assert nojson["status"] == "fail" and "search.formats" in nojson["detail"]
    assert verify.check_provider("search", FakeHttp({"/search": ConnectionError("refused")}))["status"] == "fail"


def test_fixture_provider_and_one_label_when_both_tiers_share_an_engine(monkeypatch):
    r = verify.check_provider("search", FakeHttp())
    assert r["status"] == "ok" and "search and deep tier (fixture)" in r["label"]
    monkeypatch.setenv("SHADOWCRUMBS_FIXTURE", "/nope.json")
    assert verify.check_provider("search", FakeHttp())["status"] == "fail"
    assert [k for k, _ in verify.plan() if k == "provider"] == ["provider"]                 # one check, not two


# running, remembering, leaking --------------------------------------------------------------------

def test_run_checks_covers_every_source_remembers_results_and_sorts_worst_first(monkeypatch, demo):
    monkeypatch.setenv("HIBP_API_KEY", KEY)
    monkeypatch.setattr(deep_plugins, "dns_lookup", lambda n, t: (["1.1.1.1"], "ok"))
    http = FakeHttp({"subscription/status": Resp(401)})
    results = verify.run_checks(http=http)
    ids = {r["id"] for r in results}
    assert {f"source:{n}" for n in REGISTRY} <= ids and "provider:search" in ids
    assert results[0]["id"] == "source:hibp_breaches" and results[0]["status"] == "fail"            # worst first
    assert [r["status"] for r in results] == sorted((r["status"] for r in results), key=verify.STATUSES.index)
    saved = verify.last()
    assert saved["checked_at"] and saved["checks"]["source:hibp_breaches"]["status"] == "fail"
    assert all(len(r["checked_at"]) == 19 for r in results)

    verify.run_checks(["rdap"], http=FakeHttp())                                                    # a partial run keeps the rest
    again = verify.last()["checks"]
    assert again["source:hibp_breaches"]["status"] == "fail" and "source:rdap" in again


def test_only_filter_accepts_names_and_provider_ids():
    got = {r["id"] for r in verify.run_checks(["rdap", "provider:deep"], http=FakeHttp())}
    assert got == {"source:rdap", "provider:deep"}


def test_a_key_in_an_error_message_never_survives_anywhere(monkeypatch, tmp_path):
    monkeypatch.setenv("HIBP_API_KEY", KEY)
    monkeypatch.setenv("GITHUB_TOKEN", KEY + "-gh")
    leaky = {"subscription/status": ConnectionError(f"failed for url with hibp-api-key: {KEY} and token={KEY}"),
             "rate_limit": RuntimeError(f"Authorization: Bearer {KEY}-gh rejected")}
    http = FakeHttp(leaky)
    results = verify.run_checks(["hibp_breaches", "github_code_search"], http=http)
    assert all(r["status"] == "fail" for r in results)
    blob = json.dumps(results) + (config.data_dir() / "verify.json").read_text()
    blob += "\n".join(__import__("shadowcrumbs.log", fromlist=["tail"]).tail(500, "debug"))
    assert KEY not in blob and "***" in blob
    assert all(KEY not in url for _, url, _ in http.calls)                                           # keys only ever in headers


def test_no_check_contacts_a_client(monkeypatch, demo):
    monkeypatch.setenv("HIBP_API_KEY", KEY)
    monkeypatch.setenv("GITHUB_TOKEN", KEY)
    monkeypatch.setenv("URLSCAN_API_KEY", KEY)
    monkeypatch.setattr(deep_plugins, "dns_lookup", lambda n, t: pytest.fail("looked up " + n) if "acme" in n else (["1.1.1.1"], "ok"))
    http = FakeHttp()
    verify.run_checks(http=http)
    assert http.calls and not any("acme" in url for _, url, _ in http.calls)                          # the demo target is acme-demo.test
    hosts = {url.split("/")[2] for _, url, _ in http.calls}
    assert hosts <= {"haveibeenpwned.com", "api.github.com", "urlscan.io", "rdap.org", "crt.sh", "web.archive.org"}


# API and command line -----------------------------------------------------------------------------

@pytest.fixture
def client():
    from shadowcrumbs.app import app
    return TestClient(app)


def wait_idle(client, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        st = client.get("/api/verify").json()
        if st["state"] == "idle":
            return st
        time.sleep(0.05)
    raise AssertionError("verification never finished")


def test_api_runs_in_the_background_and_returns_the_results(client, monkeypatch):
    monkeypatch.setattr(verify, "HttpClient", lambda **k: FakeHttp())
    assert client.get("/api/verify").json()["results"] == []
    r = client.post("/api/verify", json={"only": ["rdap", "crtsh"]})
    assert r.status_code == 202
    st = wait_idle(client)
    assert st["error"] is None and {x["id"] for x in st["results"]} == {"source:rdap", "source:crtsh"} and st["checked_at"]
    assert client.post("/api/verify").status_code == 202                                            # no body means everything
    assert len(wait_idle(client)["results"]) > 10


def test_api_refuses_a_second_run_while_one_is_going(client, monkeypatch):
    gate = __import__("threading").Event()

    class Slow(FakeHttp):
        def get_json(self, url, timeout=None):
            gate.wait(5)
            return super().get_json(url)
    monkeypatch.setattr(verify, "HttpClient", lambda **k: Slow())
    assert client.post("/api/verify", json={"only": ["rdap"]}).status_code == 202
    assert client.get("/api/verify").json()["state"] == "running"
    assert client.post("/api/verify").status_code == 409
    gate.set()
    wait_idle(client)


def test_command_line_exit_codes_and_json(monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("verify_sources", Path(__file__).resolve().parent.parent / "tools" / "verify_sources.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    monkeypatch.setattr(verify, "HttpClient", lambda **k: FakeHttp())
    assert tool.main(["rdap", "crtsh"]) == 0
    assert "OK" in capsys.readouterr().out
    monkeypatch.setattr(verify, "HttpClient", lambda **k: FakeHttp({"rdap.org": Resp(500)}))
    assert tool.main(["rdap"]) == 1
    assert "FAIL" in capsys.readouterr().out
    monkeypatch.setattr(verify, "HttpClient", lambda **k: FakeHttp())
    assert tool.main(["hibp_breaches"]) == 0                       # a missing key is not a failure...
    assert tool.main(["hibp_breaches", "--strict"]) == 1           # ...unless you ask for strict
    capsys.readouterr()
    tool.main(["rdap", "--json"])
    assert json.loads(capsys.readouterr().out)[0]["id"] == "source:rdap"
