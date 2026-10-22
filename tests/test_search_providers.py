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
    assert search.make_provider("search").name == "brave"   # a key means the API leads on both tiers
    assert search.make_provider("deep").name == "brave"
    assert [p.name for p in search.make_chain("search")] == ["brave", "ddg"]
    monkeypatch.setenv("SHADOWCRUMBS_SEARXNG_URL", "http://127.0.0.1:8888")
    assert [p.name for p in search.make_chain("deep")] == ["brave", "searxng", "ddg"]
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH", "fixture")
    assert config.search_chain("search") == ["fixture"]    # forcing one turns the fallback off


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


class JsonResp(Resp):
    def __init__(self, data, status=200):
        super().__init__("", status)
        self._data = data

    def json(self):
        return self._data


def test_searxng_retries_once_when_engines_are_suspended_then_refuses_to_pass_off_empty(monkeypatch):
    monkeypatch.setattr(search.time, "sleep", lambda s: None)
    suspended = {"results": [], "unresponsive_engines": [["brave", "Suspended: too many requests"], ["duckduckgo", "CAPTCHA"]]}
    calls = []

    def fake_get(url, **k):
        calls.append(1)
        return JsonResp(suspended)

    monkeypatch.setattr(search.requests, "get", fake_get)
    with pytest.raises(search.SearchBlocked, match="brave: Suspended.*duckduckgo: CAPTCHA"):
        search.SearXNG("http://x").search("q", 5)
    assert len(calls) == 2                                   # one retry, no more


def test_searxng_retry_can_succeed_and_a_true_empty_is_not_retried(monkeypatch):
    monkeypatch.setattr(search.time, "sleep", lambda s: None)
    replies = [{"results": [], "unresponsive_engines": [["brave", "Suspended"]]},
               {"results": [{"title": "T", "url": "https://a.test", "content": "c"}]}]
    monkeypatch.setattr(search.requests, "get", lambda *a, **k: JsonResp(replies.pop(0)))
    assert [r.url for r in search.SearXNG("http://x").search("q", 5)] == ["https://a.test"]

    calls = []
    monkeypatch.setattr(search.requests, "get", lambda *a, **k: calls.append(1) or JsonResp({"results": []}))
    assert search.SearXNG("http://x").search("q", 5) == [] and len(calls) == 1


# the fallback chain ------------------------------------------------------------------------------

def test_a_throttled_engine_hands_over_to_the_next_and_stays_out_for_the_run():
    brave, searx = Blocking(name="brave"), Blocking(name="searxng", ok=99)
    c = _client([brave, searx])
    assert len(c.search("q1")) == 1 and len(c.search("q2")) == 1
    assert brave.calls == 1 and searx.calls == 2         # brave was not asked again once it blocked
    assert not c.blocked and c.provider.name == "searxng"
    assert not config.block_marker().exists()            # nothing about DuckDuckGo was learned


def test_the_run_ends_only_when_every_engine_has_blocked():
    brave, ddg = Blocking(name="brave"), Blocking(name="ddg")
    c = _client([brave, ddg])
    with pytest.raises(search.SearchBlocked):
        c.search("q1")
    assert c.blocked and config.block_marker().exists()  # the DuckDuckGo block is remembered
    with pytest.raises(search.SearchBlocked):
        c.search("q2")
    assert brave.calls == 1 and ddg.calls == 1


def test_duckduckgo_as_a_fallback_still_respects_an_earlier_block():
    config.block_marker().parent.mkdir(parents=True, exist_ok=True)
    config.block_marker().write_text(json.dumps({"at": time.time()}))
    brave, ddg = Blocking(name="brave"), Blocking(name="ddg", ok=99)
    with pytest.raises(search.SearchBlocked, match="blocked this IP"):
        _client([brave, ddg]).search("q")
    assert ddg.calls == 0                                 # not one request went to DuckDuckGo
    stamp = json.loads(config.block_marker().read_text())["at"]
    assert time.time() - stamp < 5                         # and the quiet period was not restarted


def test_brave_rejecting_the_key_is_a_block_so_the_chain_carries_on(monkeypatch):
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    monkeypatch.setattr(search.requests, "get", lambda *a, **k: Resp("", 401))
    with pytest.raises(search.SearchBlocked, match="BRAVE_API_KEY"):
        search.Brave().search("q", 5)


def test_brave_gets_a_short_pace_unless_you_set_one(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH_DELAY", raising=False)
    waits = []
    c = search.SearchClient([search.Brave.__new__(search.Brave), Blocking(name="ddg", ok=9)], None, sleep=waits.append)
    assert c._delay_for(c.chain[0]) == search.BRAVE_PACE and c._delay_for(c.chain[1]) == 8
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH_DELAY", "5")
    c = search.SearchClient([search.Brave.__new__(search.Brave)], None, sleep=waits.append)
    assert c._delay_for(c.chain[0]) == 5                   # your setting wins


# Exa -----------------------------------------------------------------------------------------------

EXA_OK = {
    "requestId": "r1",
    "results": [
        {"title": "Careers at Acme", "url": "https://acme-demo.test/careers", "highlights": ["Join the", "Acme team."]},
        {"title": "Bare", "url": "https://acme-demo.test/x"},
        {"title": "Str", "url": "https://acme-demo.test/y", "highlights": "one   string"},
    ],
}


def test_exa_is_last_in_the_chain_and_only_with_a_key(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH", raising=False)
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    assert [p.name for p in search.make_chain("search")] == ["ddg"]
    monkeypatch.setenv("EXA_API_KEY", "k")
    assert [p.name for p in search.make_chain("search")] == ["ddg", "exa"]
    assert search.make_provider("search").name == "ddg"          # a free account's credits are not spent first
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    monkeypatch.setenv("SHADOWCRUMBS_SEARXNG_URL", "http://127.0.0.1:8888")
    assert [p.name for p in search.make_chain("deep")] == ["brave", "searxng", "ddg", "exa"]
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH", "exa")
    assert config.search_chain("deep") == ["exa"]                # forcing it still works


def test_exa_request_and_parsing(monkeypatch):
    monkeypatch.setenv("EXA_API_KEY", "secret-exa-key")
    sent = {}

    def fake_post(url, **kw):
        sent.update(url=url, **kw)
        return JsonResp(EXA_OK)

    monkeypatch.setattr(search.requests, "post", fake_post)
    out = search.Exa().search('site:acme-demo.test "careers"', 2)
    assert sent["url"] == "https://api.exa.ai/search"
    assert sent["headers"]["x-api-key"] == "secret-exa-key"
    assert sent["json"]["query"] == 'site:acme-demo.test "careers"' and sent["json"]["numResults"] == 2
    assert [(r.title, r.url, r.snippet) for r in out] == [
        ("Careers at Acme", "https://acme-demo.test/careers", "Join the Acme team."),
        ("Bare", "https://acme-demo.test/x", ""),
    ]                                                              # n caps the answer, a missing highlight is just empty
    assert search.Exa().search("q", 5)[2].snippet == "one string"  # a plain string highlight and spacing are tidied


def test_exa_dropping_the_site_restriction_counts_as_no_results(monkeypatch):
    """Exa answers with unrelated pages when nothing matched site:. Those must never become findings."""
    monkeypatch.setenv("EXA_API_KEY", "k")
    relaxed = dict(EXA_OK, notices=[{"code": "RESTRICTIONS_RELAXED", "details": {"relaxed": [{"kind": "site"}]}}])
    monkeypatch.setattr(search.requests, "post", lambda *a, **k: JsonResp(relaxed))
    assert search.Exa().search("site:acme-demo.test", 10) == []


@pytest.mark.parametrize("status", [401, 402, 403, 429, 503])
def test_exa_refusals_are_blocks_so_the_run_stops_spending_on_it(monkeypatch, status):
    monkeypatch.setenv("EXA_API_KEY", "k")
    monkeypatch.setattr(search.requests, "post", lambda *a, **k: Resp("", status))
    with pytest.raises(search.SearchBlocked, match="Exa"):
        search.Exa().search("q", 5)


def test_exa_without_a_key_says_so(monkeypatch):
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="EXA_API_KEY"):
        search.Exa().search("q", 5)


def test_exa_only_answers_after_everything_ahead_of_it_has_blocked():
    ddg, exa = Blocking(name="ddg"), Blocking(name="exa", ok=99)
    c = _client([ddg, exa])
    assert len(c.search("q1")) == 1 and c.provider.name == "exa"
    c.search("q2")
    assert ddg.calls == 1 and exa.calls == 2                       # DuckDuckGo is not asked again this run


def test_exa_blocking_ends_live_searching_and_is_not_asked_again():
    ddg, exa = Blocking(name="ddg"), Blocking(name="exa")
    c = _client([ddg, exa])
    for q in ("q1", "q2", "q3"):
        with pytest.raises(search.SearchBlocked):
            c.search(q)
    assert ddg.calls == 1 and exa.calls == 1 and c.blocked          # one refusal each, then nothing more is sent


def test_exa_blocking_does_not_set_the_duckduckgo_block_marker():
    c = _client([Blocking(name="brave", ok=99), Blocking(name="exa")])
    c.search("q")
    assert not config.block_marker().exists()


def test_exa_gets_a_short_pace_unless_you_set_one(monkeypatch):
    monkeypatch.delenv("SHADOWCRUMBS_SEARCH_DELAY", raising=False)
    c = search.SearchClient([Blocking(name="ddg"), search.Exa()], None, sleep=lambda s: None)
    assert c._delay_for(c.chain[1]) == search.EXA_PACE and c._delay_for(c.chain[0]) == 8
    monkeypatch.setenv("SHADOWCRUMBS_SEARCH_DELAY", "5")
    c = search.SearchClient([search.Exa()], None, sleep=lambda s: None)
    assert c._delay_for(c.chain[0]) == 5                           # your setting wins


# off target answers ---------------------------------------------------------------------------------

class Fixed:
    """A provider that always answers with the same URLs, whatever it was asked."""

    def __init__(self, urls, name="searxng"):
        self.name, self.urls, self.calls = name, urls, 0

    def search(self, query, n):
        self.calls += 1
        return [search.Result(f"t{i}", u, "") for i, u in enumerate(self.urls)]


@pytest.mark.parametrize("query, hosts", [
    ("site:acme-demo.test", ["acme-demo.test"]),
    ("site:acme-demo.test -www", ["acme-demo.test"]),
    ("site:acme-demo.test -site:mail.acme-demo.test", ["acme-demo.test"]),   # an exclusion is not a restriction
    ("site:a.test OR site:b.test login", ["a.test", "b.test"]),
    ("(site:acme-demo.test filetype:pdf)", ["acme-demo.test"]),
    ("site:https://Acme-Demo.test/path?x=1", ["acme-demo.test"]),
    ("site:*.acme-demo.test", ["acme-demo.test"]),
    ("site:acme-demo.test:8443", ["acme-demo.test"]),
    ("site:.gov report", [".gov"]),
    ('"@acme-demo.test" filetype:pdf', []),
])
def test_site_terms_are_read_from_a_query(query, hosts):
    assert search.site_hosts(query) == hosts


def test_on_site_takes_subdomains_but_not_lookalikes():
    h = ["acme-demo.test"]
    assert search.on_site("https://acme-demo.test/x", h) and search.on_site("https://VPN.acme-demo.test./", h)
    assert not search.on_site("https://evilacme-demo.test/", h)         # shares the ending, is not a subdomain
    assert not search.on_site("https://acme-demo.test.evil.example/", h)
    assert not search.on_site("not a url", h) and not search.on_site("", h)
    assert search.on_site("https://www.nsa.gov/x", [".gov"]) and not search.on_site("https://gov.evil.example/", [".gov"])


def test_off_target_answers_are_dropped_and_the_engine_is_named(demo):
    p = Fixed(["https://acme-demo.test/a", "https://today.example/junk", "https://vpn.acme-demo.test/", "https://textfree.example/"])
    c = search.SearchClient(p, demo, delay=0, sleep=lambda s: None)
    logged = []
    c.log = lambda msg, level="info": logged.append((level, msg))
    out = c.search("site:acme-demo.test filetype:pdf")
    assert [r.url for r in out] == ["https://acme-demo.test/a", "https://vpn.acme-demo.test/"]
    warn = [m for lvl, m in logged if lvl == "warning"]
    assert len(warn) == 1 and "[searxng]" in warn[0] and "dropped 2 of 4" in warn[0]
    again = search.SearchClient(Fixed([]), demo, delay=0, sleep=lambda s: None).search("site:acme-demo.test filetype:pdf")
    assert [r.url for r in again] == [r.url for r in out]               # the cache holds the cleaned answer, not the junk


def test_an_answer_with_nothing_on_the_site_is_not_cached(demo):
    """The engine ignored the operator. That says nothing about the client, so a later run must ask again."""
    junk = Fixed(["https://today.example/junk", "https://textfree.example/"])
    assert search.SearchClient(junk, demo, delay=0, sleep=lambda s: None).search("site:acme-demo.test") == []
    good = Fixed(["https://acme-demo.test/real"])
    out = search.SearchClient(good, demo, delay=0, sleep=lambda s: None).search("site:acme-demo.test")
    assert good.calls == 1 and [r.url for r in out] == ["https://acme-demo.test/real"]


def test_a_truly_empty_answer_is_still_cached(demo):
    empty = Fixed([])
    search.SearchClient(empty, demo, delay=0, sleep=lambda s: None).search("site:acme-demo.test")
    later = Fixed(["https://acme-demo.test/x"])
    assert search.SearchClient(later, demo, delay=0, sleep=lambda s: None).search("site:acme-demo.test") == []
    assert later.calls == 0                                             # nothing came back, nothing was dropped, so it counts


def test_queries_without_a_site_term_and_demo_data_are_left_alone(demo):
    urls = ["https://one.example/", "https://two.example/"]
    plain = search.SearchClient(Fixed(urls), demo, delay=0, sleep=lambda s: None)
    assert len(plain.search('"@acme-demo.test" filetype:pdf')) == 2
    assert len(plain.search("login -site:one.example")) == 2     # only an exclusion
    canned = search.SearchClient(Fixed(urls, name="fixture"), None, delay=0, sleep=lambda s: None)
    assert len(canned.search("site:acme-demo.test")) == 2               # canned demo results are not an engine's answer
