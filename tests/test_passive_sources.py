import pytest

from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.store import Store

load_plugins()


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeHttp:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.responses.pop(0)


@pytest.fixture(autouse=True)
def no_key(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)


@pytest.fixture
def store():
    return Store.create("Passive", company="Acme Demo Corp", domain="acme-demo.test")


def run(name, store, http):
    meta = store.meta()
    ctx = Context(target={k: meta[k] for k in ("company", "domain", "ip")}, search=None, http=http, store=store)
    return list(REGISTRY[name].run(ctx))


def scan(host, ip, asn="AS64500 EXAMPLENET - Example Net, US", server="nginx", title="Portal", when="2026-10-07T10:00:00.000Z", uid="u1"):
    return {"_id": uid, "task": {"time": when, "uuid": uid},
            "page": {"domain": host, "ip": ip, "asnname": asn, "server": server, "title": title, "country": "US"}}


def test_urlscan_turns_scans_into_subdomains_infrastructure_and_tech(store):
    http = FakeHttp(Resp(200, {"results": [
        scan("vpn.acme-demo.test", "203.0.113.10", uid="a"),
        scan("vpn.acme-demo.test", "203.0.113.11", uid="b", when="2026-10-09T10:00:00.000Z"),
        scan("acme-demo.test", "203.0.113.5", server="Microsoft-IIS/10.0", uid="c"),
    ]}))
    out = run("urlscan_search", store, http)
    by_cat = lambda c: [f for f in out if f.category == c]
    assert [f.value for f in by_cat("subdomains")] == ["vpn.acme-demo.test"]      # the bare domain is not a subdomain
    assert by_cat("subdomains")[0].url == "https://urlscan.io/result/a/"
    infra = {f.value: f for f in by_cat("infrastructure")}
    vpn = infra["vpn.acme-demo.test on AS64500 EXAMPLENET - Example Net, US: 203.0.113.10, 203.0.113.11"]
    assert "2 addresses" in vpn.notes and "2026-10-09" in vpn.notes
    assert vpn.url == "https://urlscan.io/result/b/"                              # evidence points at the newest scan
    assert {f.value for f in by_cat("tech")} >= {"Server: nginx", "Server: Microsoft-IIS/10.0"}


def test_urlscan_drops_scans_that_only_mention_the_domain(store):
    http = FakeHttp(Resp(200, {"results": [
        scan("evil-acme-demo.test", "198.51.100.9"),
        scan("acme-demo.test.attacker.test", "198.51.100.10"),
        scan("mail.acme-demo.test", "203.0.113.20"),
    ]}))
    out = run("urlscan_search", store, http)
    assert [f.value for f in out if f.category == "subdomains"] == ["mail.acme-demo.test"]
    assert not any("198.51.100" in f.value for f in out)


def test_urlscan_summarises_many_addresses_instead_of_flooding(store):
    rows = [scan("cdn.acme-demo.test", f"203.0.113.{i}", uid=str(i)) for i in range(1, 9)]
    out = run("urlscan_search", store, FakeHttp(Resp(200, {"results": rows})))
    infra = [f for f in out if f.category == "infrastructure"]
    assert len(infra) == 1 and "and 4 more" in infra[0].value and "8 addresses" in infra[0].notes


def test_urlscan_query_is_plain_and_the_key_is_optional(store, monkeypatch):
    http = FakeHttp(Resp(200, {"results": []}))
    run("urlscan_search", store, http)
    url, kw = http.calls[0]
    assert kw["params"]["q"] == "page.domain:acme-demo.test"                      # anonymous users may not use wildcards
    assert "API-Key" not in kw["headers"]
    monkeypatch.setenv("URLSCAN_API_KEY", "k")
    store2 = Store.create("Keyed", domain="acme-demo.test")
    http2 = FakeHttp(Resp(200, {"results": []}))
    run("urlscan_search", store2, http2)
    assert http2.calls[0][1]["headers"]["API-Key"] == "k"


def test_urlscan_caches_so_a_rerun_makes_no_request(store):
    run("urlscan_search", store, FakeHttp(Resp(200, {"results": [scan("vpn.acme-demo.test", "203.0.113.10")]})))
    again = FakeHttp()
    assert run("urlscan_search", store, again) and again.calls == []


@pytest.mark.parametrize("status,match", [
    (429, "rate limit"), (403, "URLSCAN_API_KEY"), (401, "URLSCAN_API_KEY"), (400, "rejected the search query"),
])
def test_urlscan_errors_are_clear(store, status, match):
    with pytest.raises(RuntimeError, match=match):
        run("urlscan_search", store, FakeHttp(Resp(status, headers={"X-Rate-Limit-Reset-After": "40"})))


def test_urlscan_empty_result_is_fine(store):
    assert run("urlscan_search", store, FakeHttp(Resp(200, {"results": []}))) == []


# --- GitHub code search ------------------------------------------------------------------

FAKE_TOKEN = "fake-github-token-for-tests-0123456789"   # nothing like a real token, so no scanner mistakes it for one
PLANTED_SECRET = "Sup3rS3cretPW!"


@pytest.fixture
def gh_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", FAKE_TOKEN)
    monkeypatch.setattr("shadowcrumbs.plugins.passive_sources.time.sleep", lambda s: None)


def hit(repo, path, fragment, fork=False):
    return {"path": path, "html_url": f"https://github.com/{repo}/blob/main/{path}",
            "repository": {"full_name": repo, "fork": fork},
            "text_matches": [{"fragment": fragment}]}


def everything_stored(store):
    """All text the engagement database holds that came from this run: findings, notes, and the query cache."""
    import json
    with store.conn() as c:
        cache = [row["results"] for row in c.execute("SELECT results FROM search_cache")]
    return json.dumps(store.findings()) + "".join(cache)


def test_github_unavailable_without_a_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert REGISTRY["github_code_search"].unavailable() == "needs GITHUB_TOKEN"


def test_github_extracts_repos_hosts_and_addresses(store, gh_token):
    http = FakeHttp(Resp(200, {"items": [
        hit("someorg/infra", "deploy/.env", "API=https://vpn.acme-demo.test/v1 contact ops@acme-demo.test"),
        hit("someorg/infra", "README.md", "see acme-demo.test"),
        hit("other/tool", "src/main.py", "host = 'mail.acme-demo.test'"),
        hit("forker/infra", "deploy/.env", "vpn.acme-demo.test", fork=True),
    ]}))
    out = run("github_code_search", store, http)
    by = lambda c: {f.value: f for f in out if f.category == c}
    infra = by("infrastructure")
    assert set(infra) == {"Public code mentions acme-demo.test: someorg/infra", "Public code mentions acme-demo.test: other/tool"}
    big = infra["Public code mentions acme-demo.test: someorg/infra"]
    assert big.confidence == 55 and "2 files" in big.notes and "config-like" in big.notes
    assert infra["Public code mentions acme-demo.test: other/tool"].confidence == 40
    assert set(by("subdomains")) == {"vpn.acme-demo.test", "mail.acme-demo.test"}
    assert set(by("emails")) == {"ops@acme-demo.test"}


def test_github_never_keeps_code_or_the_token(store, gh_token):
    frag = f'password = "{PLANTED_SECRET}"  # db.acme-demo.test  token {FAKE_TOKEN}'
    http = FakeHttp(Resp(200, {"items": [hit("someorg/leaky", "config.py", frag)]}))
    out = run("github_code_search", store, http)
    assert any(f.value == "db.acme-demo.test" for f in out)             # the hostname was kept
    stored = everything_stored(store) + "".join(f"{f.value}{f.notes}{f.url}" for f in out)
    assert PLANTED_SECRET not in stored and FAKE_TOKEN not in stored
    assert http.calls[0][1]["headers"]["Authorization"] == f"Bearer {FAKE_TOKEN}"   # only ever in the request header


def test_github_caches_so_a_rerun_makes_no_request(store, gh_token):
    run("github_code_search", store, FakeHttp(Resp(200, {"items": [hit("a/b", "x.py", "vpn.acme-demo.test")]})))
    again = FakeHttp()
    assert run("github_code_search", store, again) and again.calls == []


def test_github_pages_only_while_results_are_full(store, gh_token):
    full = [hit(f"org{i}/r", "a.py", "x.acme-demo.test") for i in range(100)]
    http = FakeHttp(Resp(200, {"items": full}), Resp(200, {"items": [hit("last/one", "b.py", "y.acme-demo.test")]}))
    out = run("github_code_search", store, http)
    assert len(http.calls) == 2 and http.calls[1][1]["params"]["page"] == 2
    assert any("last/one" in f.value for f in out)                      # the second page was read
    assert len([f for f in out if f.category == "infrastructure"]) == 50


@pytest.mark.parametrize("status,match", [
    (401, "GITHUB_TOKEN"), (403, "rate limit"), (429, "rate limit"), (422, "rejected the search query"),
])
def test_github_errors_are_clear_and_never_echo_the_token(store, gh_token, status, match):
    with pytest.raises(RuntimeError, match=match) as e:
        run("github_code_search", store, FakeHttp(Resp(status, headers={"Retry-After": "30"})))
    assert FAKE_TOKEN not in str(e.value)


def test_github_skips_vendored_copies_of_other_libraries(store, gh_token):
    http = FakeHttp(Resp(200, {"items": [
        hit("a/app", "myvenv/Lib/site-packages/requests/api.py", "vpn.acme-demo.test"),
        hit("a/app", "node_modules/x/index.js", "mail.acme-demo.test"),
        hit("a/app", "deploy/hosts.yml", "www.acme-demo.test"),
    ]}))
    out = run("github_code_search", store, http)
    infra = [f for f in out if f.category == "infrastructure"]
    assert len(infra) == 1 and "1 file mentions" in infra[0].notes and "deploy/hosts.yml" in infra[0].notes
    assert {f.value for f in out if f.category == "subdomains"} == {"www.acme-demo.test"}


def test_github_ignores_private_and_internal_repos(store, gh_token):
    private = hit("me/secret-infra", "prod.env", "db.acme-demo.test")
    private["repository"]["private"] = True
    internal = hit("corp/internal", "a.py", "intranet.acme-demo.test")
    internal["repository"]["visibility"] = "internal"
    http = FakeHttp(Resp(200, {"items": [private, internal, hit("open/repo", "a.py", "www.acme-demo.test")]}))
    out = run("github_code_search", store, http)
    assert [f.value for f in out if f.category == "infrastructure"] == ["Public code mentions acme-demo.test: open/repo"]
    stored = everything_stored(store)
    assert "secret-infra" not in stored and "intranet" not in stored and "db.acme-demo.test" not in stored
