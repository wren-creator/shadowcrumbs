"""wayback_urls: patient with a slow Internet Archive, and stops when it is rate limiting us."""
import importlib.util
from pathlib import Path

import pytest
import requests

from shadowcrumbs.plugin import REGISTRY, Context

PATH = Path(__file__).resolve().parent.parent / "plugins_user" / "wayback_urls.py"


@pytest.fixture
def mod():
    spec = importlib.util.spec_from_file_location("wayback_under_test", PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    yield m
    REGISTRY.pop("wayback_urls", None)       # it is a network source, keep it out of the other tests


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


class Http:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def get(self, url, timeout=None, **kw):
        self.calls.append(timeout)
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def run(mod, http):
    logs = []
    ctx = Context(target={"domain": "acme.test"}, search=None, http=http, store=None, log=lambda m, level="info": logs.append((level, m)))
    return list(mod.WaybackUrls().run(ctx)), logs


ROWS = [["original"], ["http://acme.test/admin/login"], ["http://acme.test/about"], ["http://acme.test/backup.sql"]]


def test_a_timeout_then_a_busy_answer_then_success(mod, monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    http = Http(requests.ReadTimeout(), Resp(503), Resp(200, ROWS))
    found, logs = run(mod, http)
    assert [f.url for f in found] == ["http://acme.test/admin/login", "http://acme.test/backup.sql"]   # /about is boring
    assert len(http.calls) == 3 and all(t == mod.TRY_TIMEOUT for t in http.calls)
    assert [l for l, _ in logs] == ["warning", "warning"]


def test_gives_up_with_a_short_readable_error_after_three_tries(mod, monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    http = Http(requests.ReadTimeout(), requests.ConnectionError(), Resp(503))
    with pytest.raises(RuntimeError, match=r"did not answer after 3 tries \(HTTP 503\)"):
        run(mod, http)
    assert len(http.calls) == 3


def test_a_403_stops_at_once_because_asking_again_makes_it_worse(mod, monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: pytest.fail("must not wait and retry on a 403"))
    http = Http(Resp(403))
    with pytest.raises(RuntimeError, match="asked too often"):
        run(mod, http)
    assert len(http.calls) == 1


def test_an_empty_archive_is_not_an_error(mod):
    found, _ = run(mod, Http(Resp(200, [])))
    assert found == []


def test_verify_calls_a_slow_archive_a_warning_not_a_failure(mod):
    class Slow:
        def get_json(self, url, timeout=None):
            raise requests.ReadTimeout()
    status, detail = mod.WaybackUrls().verify(Slow())
    assert status == "warn" and "retries" in detail


def test_an_error_page_sent_as_a_200_counts_as_a_failed_try(mod, monkeypatch):
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)

    class Html(Resp):
        def json(self):
            raise ValueError("not json")
    found, _ = run(mod, Http(Html(200), Resp(200, ROWS)))
    assert len(found) == 2


def test_the_host_name_never_makes_a_url_interesting(mod):
    rows = [["original"], ["http://devcorp.test/about"], ["http://devcorp.test/staging/login"], ["https://admin.devcorp.test/"]]
    found, _ = run(mod, Http(Resp(200, rows)))
    assert [f.url for f in found] == ["http://devcorp.test/staging/login"]


def test_well_known_files_feeds_and_data_files_are_kept_but_a_pdf_is_not(mod):
    urls = ["/.well-known/ai-plugin.json", "/.well-known/assetlinks.json", "/sitemap.xml", "/feed.xml",
            "/index.xml", "/export/users.csv", "/reports/q3.pdf", "/about"]
    found, _ = run(mod, Http(Resp(200, [["original"]] + [[f"https://acme.test{u}"] for u in urls])))
    assert [f.value.split("acme.test")[1] for f in found] == urls[:6]
    assert found[0].notes.startswith("[Well-known metadata file]")
    assert found[2].notes.startswith("[Sitemap or feed]")
    assert found[5].notes.startswith("[Data or export file]")
