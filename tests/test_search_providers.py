"""Parser tests against a representative DuckDuckGo HTML page.

This pins the parsing logic. The first live run (2026-10-07) confirmed the layout, plus one surprise: sponsored results. It does not prove DuckDuckGo still serves this layout, so if live
searches come back empty, compare a real response with SAMPLE below first.
"""
import json
import time

import pytest

from shadowcrumbs import config, search

SAMPLE = """
<html><body>
<div class="result results_links web-result">
  <h2 class="result__title"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fvpn.acme-demo.test%2Flogin&rut=abc">VPN Login</a></h2>
  <a class="result__snippet" href="x">Remote access for <b>Acme</b> staff.</a>
</div>
<div class="result"><a class="result__a" href="https://direct.example.org/page">Direct link</a></div>
<div class="result"><span>no anchor here</span></div>
<div class="result result--ad"><a class="result__a" href="https://duckduckgo.com/y.js?ad_domain=adobe.com&ad_provider=bingv7aa">Free online PDF editor</a></div>
<div class="result"><a class="result__a" href="//duckduckgo.com/y.js?ad_domain=sodapdf.com">Soda PDF</a></div>
</body></html>
"""


class Resp:
    def __init__(self, text, status=200):
        self.text, self.status_code = text, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def test_ddg_parse_and_unwrap(monkeypatch):
    monkeypatch.setattr(search.requests, "post", lambda *a, **k: Resp(SAMPLE))
    out = search.DuckDuckGoHTML().search("site:acme-demo.test", 10)
    assert [(r.title, r.url) for r in out] == [
        ("VPN Login", "https://vpn.acme-demo.test/login"),
        ("Direct link", "https://direct.example.org/page"),
    ]
    assert out[0].snippet == "Remote access for Acme staff."


def test_ddg_sponsored_results_are_dropped(monkeypatch):
    """Found on the first live run: ads arrive as ordinary-looking results. They must never become findings."""
    monkeypatch.setattr(search.requests, "post", lambda *a, **k: Resp(SAMPLE))
    urls = [r.url for r in search.DuckDuckGoHTML().search("site:acme-demo.test", 10)]
    assert not any("y.js" in u or "ad_domain" in u for u in urls)


@pytest.mark.parametrize("resp", [Resp("", 202), Resp("", 429), Resp('<div class="anomaly-modal"></div>')])
def test_ddg_throttle_is_reported_clearly(monkeypatch, resp):
    monkeypatch.setattr(search.requests, "post", lambda *a, **k: resp)
    with pytest.raises(search.SearchBlocked, match="throttling"):
        search.DuckDuckGoHTML().search("q", 5)


def test_provider_selection(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    assert search.make_provider("search").name == "ddg"
    assert search.make_provider("deep").name == "ddg"
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    assert search.make_provider("search").name == "ddg"   # search tier stays on the engine
    assert search.make_provider("deep").name == "brave"   # deep dive upgrades to the API


class Blocking:
    """A provider that is throttled from the first call (or after `ok` good ones)."""

    def __init__(self, name="ddg", ok=0):
        self.name, self.ok, self.calls = name, ok, 0

    def search(self, query, n):
        self.calls += 1
        if self.calls <= self.ok:
            return [search.Result("t", "https://x.test/", "s")]
        raise search.SearchBlocked("slow down")


def _client(provider, delay=0):
    return search.SearchClient(provider, None, delay=delay, sleep=lambda s: None)


def test_first_throttle_stops_live_searching_for_the_run():
    p = Blocking(ok=1)
    c = _client(p)
    assert len(c.search("q1")) == 1
    with pytest.raises(search.SearchBlocked):
        c.search("q2")
    assert c.blocked and p.calls == 2
    with pytest.raises(search.SearchBlocked):
        c.search("q3")
    assert p.calls == 2                              # no retries, nothing sent while blocked


def test_a_block_is_remembered_and_the_next_run_stays_quiet():
    first = Blocking()
    with pytest.raises(search.SearchBlocked):
        _client(first).search("q")
    assert config.block_marker().exists()
    later = Blocking(ok=99)                          # the engine has recovered, but we do not know that
    with pytest.raises(search.SearchBlocked, match="blocked this IP .* minutes ago"):
        _client(later).search("q")
    assert later.calls == 0                          # not one request went out


def test_staying_quiet_ends_after_the_cooldown(monkeypatch):
    config.block_marker().parent.mkdir(parents=True, exist_ok=True)
    config.block_marker().write_text(json.dumps({"at": time.time() - 61 * 60}))
    p = Blocking(ok=99)
    assert len(_client(p).search("q")) == 1
    assert not config.block_marker().exists()        # a good answer clears the memory


def test_the_override_lets_you_try_anyway(monkeypatch):
    config.block_marker().parent.mkdir(parents=True, exist_ok=True)
    config.block_marker().write_text(json.dumps({"at": time.time()}))
    monkeypatch.setenv("SHADOWCRUMBS_IGNORE_BLOCK", "1")
    assert len(_client(Blocking(ok=99)).search("q")) == 1


def test_only_ddg_blocks_are_remembered():
    with pytest.raises(search.SearchBlocked):
        _client(Blocking(name="brave")).search("q")
    assert not config.block_marker().exists()        # a Brave rate limit says nothing about DDG


def test_cooldown_length_is_configurable(monkeypatch):
    config.block_marker().parent.mkdir(parents=True, exist_ok=True)
    config.block_marker().write_text(json.dumps({"at": time.time() - 10 * 60}))
    monkeypatch.setenv("SHADOWCRUMBS_BLOCK_MINUTES", "5")
    assert len(_client(Blocking(ok=99)).search("q")) == 1


def test_fixture_provider_is_not_paced(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH_DELAY", raising=False)   # the suite zeroes it for speed
    f = tmp_path / "f.json"
    f.write_text('{"entries": []}')
    assert search.SearchClient(search.FixtureProvider(f)).delay == 0
    assert search.SearchClient(search.DuckDuckGoHTML()).delay == 8


def test_searxng_parses_json_and_sends_no_key(monkeypatch):
    seen = {}

    class R:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [{"title": "T", "url": "https://a.test/x", "content": "snip"},
                                {"title": "U", "url": "https://b.test/y", "content": ""}]}

    def fake_get(url, **k):
        seen["url"], seen["params"] = url, k["params"]
        return R()

    monkeypatch.setattr(search.requests, "get", fake_get)
    got = search.SearXNG("http://127.0.0.1:8080/").search("site:a.test", 1)
    assert seen["url"] == "http://127.0.0.1:8080/search"
    assert seen["params"] == {"q": "site:a.test", "format": "json"}
    assert [(r.title, r.url, r.snippet) for r in got] == [("T", "https://a.test/x", "snip")]


@pytest.mark.parametrize("status,match", [(429, "rate limit"), (403, "search.formats")])
def test_searxng_refusals_are_explained(monkeypatch, status, match):
    monkeypatch.setattr(search.requests, "get", lambda *a, **k: Resp("", status))
    with pytest.raises(search.SearchBlocked, match=match):
        search.SearXNG("http://x").search("q", 5)


def test_searxng_url_wins_when_set(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    monkeypatch.setenv("SHADOWCRUMBS_SEARXNG_URL", "http://127.0.0.1:8080")
    assert search.make_provider("search").name == "searxng"
    assert search.make_provider("deep").name == "searxng"
    monkeypatch.delenv("SHADOWCRUMBS_SEARXNG_URL")
    assert search.make_provider("search").name == "ddg"
    with pytest.raises(RuntimeError, match="SEARXNG_URL"):
        search.SearXNG()
