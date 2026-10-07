"""Parser tests against a representative DuckDuckGo HTML page.

This pins the parsing logic. The first live run (2026-10-07) confirmed the layout, plus one surprise: sponsored results. It does not prove DuckDuckGo still serves this layout, so if live
searches come back empty, compare a real response with SAMPLE below first.
"""
import pytest

from shadowcrumbs import search

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


class Flaky:
    """Throttles the first `blocks` calls, then answers."""

    def __init__(self, blocks):
        self.blocks, self.calls = blocks, 0

    def search(self, query, n):
        self.calls += 1
        if self.calls <= self.blocks:
            raise search.SearchBlocked("slow down")
        return [search.Result("t", "https://x.test/", "s")]


def _client(provider, monkeypatch, backoff="60,120,240", delay=8):
    monkeypatch.setenv("SHADOWCRUMBS_BACKOFF", backoff)
    sleeps = []
    return search.SearchClient(provider, None, delay=delay, sleep=sleeps.append), sleeps


def test_throttle_cools_off_then_recovers(monkeypatch):
    c, sleeps = _client(Flaky(2), monkeypatch)
    assert len(c.search("q")) == 1
    assert c.throttle_waits == 2
    assert 60 in sleeps and 120 in sleeps          # the cool-offs, in schedule order
    assert c.delay == 32                           # 8 doubled twice, and it stays slower for the rest of the run
    assert not c.blocked


def test_throttle_gives_up_and_stops_hammering(monkeypatch):
    p = Flaky(99)
    c, _ = _client(p, monkeypatch)
    with pytest.raises(search.SearchBlocked):
        c.search("q1")
    assert p.calls == 4 and c.blocked              # first try plus three retries
    with pytest.raises(search.SearchBlocked):
        c.search("q2")
    assert p.calls == 4                            # the circuit is open, no more requests sent


def test_backoff_can_be_turned_off(monkeypatch):
    p = Flaky(99)
    c, sleeps = _client(p, monkeypatch, backoff="0")
    with pytest.raises(search.SearchBlocked):
        c.search("q")
    assert p.calls == 1 and c.throttle_waits == 0


def test_delay_never_climbs_past_the_cap(monkeypatch):
    c, _ = _client(Flaky(3), monkeypatch, delay=40)
    c.search("q")
    assert c.delay == search.MAX_DELAY


def test_fixture_provider_is_not_paced(monkeypatch, tmp_path):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH_DELAY", raising=False)   # the suite zeroes it for speed
    f = tmp_path / "f.json"
    f.write_text('{"entries": []}')
    assert search.SearchClient(search.FixtureProvider(f)).delay == 0
    assert search.SearchClient(search.DuckDuckGoHTML()).delay == 8
