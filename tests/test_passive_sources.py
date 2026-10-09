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
