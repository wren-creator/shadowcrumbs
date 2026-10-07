"""Parser tests against a representative DuckDuckGo HTML page.

This pins the parsing logic. It does not prove DuckDuckGo still serves this layout, so if live
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
