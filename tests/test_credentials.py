import json

import pytest

from shadowcrumbs import engine
from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import credential_plugins as cp
from shadowcrumbs.store import Store

load_plugins()

SECRET = "Sup3rS3cretPW!"          # must never appear in any finding, note or export
MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeHttp:
    def __init__(self, get=None, post=None):
        self._get, self._post = list(get or []), list(post or [])
        self.gets, self.posts = [], []

    def get(self, url, **kw):
        self.gets.append((url, kw))
        return self._get.pop(0)

    def post(self, url, **kw):
        self.posts.append((url, kw))
        return self._post.pop(0)


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(cp.time, "sleep", lambda s: None)
    for k in ("HIBP_API_KEY", "DEHASHED_API_KEY", "SHADOWCRUMBS_BREACH_FILE"):
        monkeypatch.delenv(k, raising=False)


@pytest.fixture
def store():
    s = Store.create("Creds", company="Acme Demo Corp", domain="acme-demo.test")
    s.add_finding("emails", "jane.doe@acme-demo.test", "emails_search", "search")
    s.add_finding("emails", "marcus@acme-demo.test", "emails_search", "search")
    s.add_finding("emails", "format: first.last@acme-demo.test", "emails_search", "search")
    s.add_finding("emails", "someone@other.test", "emails_search", "search")
    return s


def run(name, store, http=None):
    meta = store.meta()
    ctx = Context(target={k: meta[k] for k in ("company", "domain", "ip")}, search=None, http=http, store=store)
    return list(REGISTRY[name].run(ctx))


def assert_no_secret(findings):
    for f in findings:
        assert SECRET not in f.value and SECRET not in (f.notes or "") and MD5 not in (f.notes or "")


@pytest.mark.parametrize("secret,expected", [
    ("", None),
    (MD5, "MD5 or NTLM looking hash"),
    ("$2b$12$" + "a" * 53, "bcrypt hash"),
    ("a" * 40, "SHA-1 looking hash"),
    (SECRET, "plaintext password, 14 characters"),
])
def test_classify_secret_keeps_none_of_it(secret, expected):
    out = cp.classify_secret(secret)
    assert out == expected
    assert SECRET not in (out or "")


def test_scope_includes_subdomains_but_not_lookalikes():
    assert cp.in_scope("a@acme-demo.test", "acme-demo.test")
    assert cp.in_scope("a@mail.acme-demo.test", "acme-demo.test")
    assert not cp.in_scope("a@evilacme-demo.test", "acme-demo.test")


def test_plugins_skip_with_a_reason_when_unconfigured(store):
    assert REGISTRY["hibp_breaches"].unavailable() == "needs HIBP_API_KEY"
    assert REGISTRY["dehashed_domain"].unavailable() == "needs DEHASHED_API_KEY"
    assert REGISTRY["breach_file_import"].unavailable() == "needs SHADOWCRUMBS_BREACH_FILE"


def test_engine_records_skipped_not_error(monkeypatch):
    s = Store.create("Gate", domain="acme-demo.test", auth_ref="SOW-1", authorized=True)
    out = engine.execute(s.slug, "deep", ["hibp_breaches"])
    row = out["plugins"][0]
    assert row["status"] == "skipped" and row["error"] == "needs HIBP_API_KEY"


# --- HIBP -------------------------------------------------------------------------------

def test_hibp_finds_breaches_and_skips_out_of_scope_and_format_rows(store, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    http = FakeHttp(get=[
        Resp(200, [{"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email addresses", "Passwords"]}]),
        Resp(404),
    ])
    out = run("hibp_breaches", store, http)
    assert [f.value for f in out] == ["Exposed credential: jane.doe@acme-demo.test in Adobe"]
    assert "Passwords were in this breach" in out[0].notes and "2013-10-04" in out[0].notes
    assert len(http.gets) == 2                                   # jane and marcus only
    assert http.gets[0][1]["headers"]["hibp-api-key"] == "k"


def test_hibp_caches_so_a_rerun_costs_nothing(store, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    run("hibp_breaches", store, FakeHttp(get=[Resp(404), Resp(404)]))
    again = FakeHttp(get=[])
    assert run("hibp_breaches", store, again) == [] and again.gets == []


def test_hibp_retries_once_on_429_then_gives_up(store, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    ok = FakeHttp(get=[Resp(429, headers={"Retry-After": "3"}), Resp(404), Resp(404)])
    assert run("hibp_breaches", store, ok) == []
    fresh = Store.create("Fresh", domain="acme-demo.test")          # the first store is cached by now
    fresh.add_finding("emails", "jane.doe@acme-demo.test", "emails_search", "search")
    with pytest.raises(RuntimeError, match="rate limit"):
        run("hibp_breaches", fresh, FakeHttp(get=[Resp(429), Resp(429)]))


def test_hibp_bad_key_is_a_clear_error(store, monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    with pytest.raises(RuntimeError, match="HIBP_API_KEY"):
        run("hibp_breaches", store, FakeHttp(get=[Resp(401)]))


# --- DeHashed ---------------------------------------------------------------------------

def test_dehashed_never_stores_the_password(store, monkeypatch):
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    body = {"entries": [
        {"email": ["jane.doe@acme-demo.test"], "password": [SECRET], "database_name": "Collection1"},
        {"email": "marcus@acme-demo.test", "hashed_password": [MD5], "database_name": "OldForum"},
        {"email": ["x@acme-demo.test"], "database_name": "NoSecret"},
        {"email": ["stranger@elsewhere.test"], "password": ["zzz"], "database_name": "Other"},
    ], "total": 4}
    http = FakeHttp(post=[Resp(200, body)])
    out = run("dehashed_domain", store, http)
    assert_no_secret(out)
    notes = {f.value: f.notes for f in out}
    assert "plaintext password, 14 characters" in notes["Exposed credential: jane.doe@acme-demo.test in Collection1"]
    assert "MD5 or NTLM looking hash" in notes["Exposed credential: marcus@acme-demo.test in OldForum"]
    assert "address only" in notes["Exposed credential: x@acme-demo.test in NoSecret"]
    assert len(out) == 3                                           # out-of-scope address dropped
    url, kw = http.posts[0]
    assert kw["json"]["query"] == "domain:acme-demo.test" and kw["headers"]["Dehashed-Api-Key"] == "k"


def test_dehashed_pages_until_a_short_page(store, monkeypatch):
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    monkeypatch.setattr(cp.DehashedDomain, "PAGE", 2)
    page = lambda n: Resp(200, {"entries": [{"email": [f"u{n}{i}@acme-demo.test"], "database_name": "D"} for i in range(2)]})
    http = FakeHttp(post=[page(1), page(2), Resp(200, {"entries": []})])
    out = run("dehashed_domain", store, http)
    assert len(out) == 4 and len(http.posts) == 3
    again = FakeHttp(post=[])
    assert len(run("dehashed_domain", store, again)) == 4 and again.posts == []   # all pages cached


@pytest.mark.parametrize("status,match", [(401, "DEHASHED_API_KEY"), (403, "DEHASHED_API_KEY"), (429, "rate limit")])
def test_dehashed_errors_are_clear(store, monkeypatch, status, match):
    monkeypatch.setenv("DEHASHED_API_KEY", "k")
    with pytest.raises(RuntimeError, match=match):
        run("dehashed_domain", store, FakeHttp(post=[Resp(status)]))


# --- file import ------------------------------------------------------------------------

def test_file_import_csv_jsonl_and_colon_lines(store, tmp_path, monkeypatch):
    csv_f = tmp_path / "collection.csv"
    csv_f.write_text(f"Email,Password,Source\njane.doe@acme-demo.test,{SECRET},Combo2019\nbob@nope.test,x,Combo2019\n")
    jsonl = tmp_path / "feed.jsonl"
    jsonl.write_text(json.dumps({"email": "marcus@acme-demo.test", "hash": MD5, "breach": "ForumX"}) + "\nnot json\n")
    txt = tmp_path / "dump.txt"
    txt.write_text(f"priya@mail.acme-demo.test:{SECRET}\n")
    results = {}
    for f in (csv_f, jsonl, txt):
        monkeypatch.setenv("SHADOWCRUMBS_BREACH_FILE", str(f))
        results[f.name] = run("breach_file_import", store)
        assert_no_secret(results[f.name])
    assert [f.value for f in results["collection.csv"]] == ["Exposed credential: jane.doe@acme-demo.test in Combo2019"]
    assert "MD5 or NTLM looking hash" in results["feed.jsonl"][0].notes
    assert results["dump.txt"][0].value == "Exposed credential: priya@mail.acme-demo.test in dump"


def test_file_import_missing_file_is_a_skip_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWCRUMBS_BREACH_FILE", str(tmp_path / "gone.csv"))
    assert "is not a file" in REGISTRY["breach_file_import"].unavailable()


def test_nothing_secret_survives_into_an_export(tmp_path, monkeypatch):
    s = Store.create("Export", domain="acme-demo.test", auth_ref="SOW-1", authorized=True)
    f = tmp_path / "x.txt"
    f.write_text(f"jane@acme-demo.test:{SECRET}\n")
    monkeypatch.setenv("SHADOWCRUMBS_BREACH_FILE", str(f))
    engine.execute(s.slug, "deep", ["breach_file_import"])
    assert s.findings("emails")
    blob = json.dumps(s.findings()) + json.dumps(s.runs())
    assert SECRET not in blob
