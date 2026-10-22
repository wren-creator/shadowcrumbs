"""The plugin templates and tools/new_plugin.py: a scaffolded source has to load, run, and not be able to escape its folder."""
import importlib.util
import sys
from pathlib import Path

import pytest

from shadowcrumbs import engine
from shadowcrumbs.plugin import LOAD_ERRORS, REGISTRY, load_plugins
from shadowcrumbs.store import Store

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("new_plugin", ROOT / "tools" / "new_plugin.py")
new_plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(new_plugin)


@pytest.fixture
def plugin_dir(tmp_path, monkeypatch):
    d = tmp_path / "plugins_user"
    monkeypatch.setenv("SHADOWCRUMBS_PLUGINS", str(d))
    load_plugins()                            # built-ins first, so they count as "before" and are never popped
    before = set(REGISTRY)
    yield d
    for n in set(REGISTRY) - before:          # the registry is global, leave it as we found it
        REGISTRY.pop(n)


def make(plugin_dir, *args):
    return new_plugin.main([*args, "--dir", str(plugin_dir)])


def test_both_templates_are_real_python_and_are_never_loaded_by_the_app(monkeypatch):
    for tier in ("search", "deep"):
        text = (ROOT / "plugins_user" / f"_template_{tier}.py").read_text()
        compile(text.replace("__CLASS__", "X").replace("__TOUCHES__", "False"), "t", "exec")
        assert "__NAME__" in text and "__CATEGORY__" in text
    load_plugins()
    monkeypatch.setenv("SHADOWCRUMBS_PLUGINS", str(ROOT / "plugins_user"))     # the real folder, templates and all
    before = set(REGISTRY)
    load_plugins()
    assert "__NAME__" not in REGISTRY and not LOAD_ERRORS
    for n in set(REGISTRY) - before:
        REGISTRY.pop(n)


def test_scaffolded_search_source_loads_and_finds_things_on_the_demo(plugin_dir, demo):
    assert make(plugin_dir, "careers_tech", "--tier", "search", "--category", "tech", "--description", "Tech hints.",
                "--query", "site:{d} careers", "--query", '"{company}" "experience with"') == 0
    load_plugins()
    p = REGISTRY["careers_tech"]
    assert (p.tier, p.categories, p.needs_any, p.description) == ("search", ("tech",), ("domain",), "Tech hints.")
    out = engine.execute(demo.slug, "search", ["careers_tech"])
    assert out["plugins"][0]["status"] == "ok" and out["plugins"][0]["found"] > 0
    assert all(f["category"] == "tech" and f["plugins"] == ["careers_tech"] for f in demo.findings("tech") if "careers_tech" in f["plugins"])


def test_a_query_about_a_missing_company_is_dropped_not_searched_as_none(plugin_dir):
    make(plugin_dir, "co_only", "--tier", "search", "--category", "tech", "--query", '"{company}" jobs')
    load_plugins()
    s = Store.create("NoCo", domain="acme-demo.test")                  # a domain, no company
    asked = []
    real = engine.SearchClient.search
    engine.SearchClient.search = lambda self, q, n=20: asked.append(q) or []
    try:
        engine.execute(s.slug, "search", ["co_only"])
    finally:
        engine.SearchClient.search = real
    assert asked == []


def test_scaffolded_deep_source_is_skipped_until_it_is_filled_in(plugin_dir, demo):
    assert make(plugin_dir, "vendor_api", "--tier", "deep", "--category", "infrastructure", "--key-env", "VENDOR_API_KEY",
                "--touches-target") == 0
    text = (plugin_dir / "vendor_api.py").read_text()
    assert "touches_target = True" in text and "KEY_ENV = 'VENDOR_API_KEY'" in text
    load_plugins()
    p = REGISTRY["vendor_api"]
    assert p.tier == "deep" and p.touches_target is True
    assert "still the template" in p.unavailable()                                # URL empty comes first
    demo.update_meta(authorized=True, auth_ref="SOW-1")
    out = engine.execute(demo.slug, "deep", ["vendor_api"])
    assert out["plugins"][0]["status"] == "skipped" and "template" in out["plugins"][0]["error"]


def test_deep_template_needs_its_key_and_never_puts_it_in_the_url(plugin_dir, monkeypatch):
    make(plugin_dir, "vendor_api", "--tier", "deep", "--category", "infrastructure", "--key-env", "VENDOR_API_KEY")
    text = (plugin_dir / "vendor_api.py").read_text().replace('URL = ""', 'URL = "https://vendor.test/search"')
    assert "https://vendor.test/search" in text
    (plugin_dir / "vendor_api.py").write_text(text)
    load_plugins()
    p = REGISTRY["vendor_api"]
    monkeypatch.delenv("VENDOR_API_KEY", raising=False)
    assert p.unavailable() == "needs VENDOR_API_KEY"
    monkeypatch.setenv("VENDOR_API_KEY", "fake-key-for-tests-1")
    assert p.unavailable() is None

    class Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"results": [{"name": "host1.acme-demo.test", "url": "https://vendor.test/h/1"}]}

    class Http:
        calls = []
        def get(self, url, **kw):
            self.calls.append((url, kw))
            return Resp()
    http = Http()
    from shadowcrumbs.plugin import Context
    found = list(p.run(Context(target={"domain": "acme-demo.test"}, search=None, http=http, store=None)))
    url, kw = http.calls[0]
    assert "fake-key" not in url and kw["headers"]["X-Api-Key"] == "fake-key-for-tests-1"
    assert found[0].category == "infrastructure" and found[0].value == "host1.acme-demo.test"


def test_scaffolded_deep_source_can_be_verified(plugin_dir, monkeypatch):
    from shadowcrumbs import verify
    make(plugin_dir, "vendor_api", "--tier", "deep", "--category", "infrastructure", "--key-env", "VENDOR_API_KEY")
    path = plugin_dir / "vendor_api.py"
    path.write_text(path.read_text().replace('URL = ""', 'URL = "https://vendor.test/search"'))
    load_plugins()
    p = REGISTRY["vendor_api"]

    class R:
        def __init__(self, code): self.status_code = code
        def raise_for_status(self): pass

    class Http:
        def __init__(self, code): self.code, self.calls = code, []
        def get(self, url, **kw):
            self.calls.append((url, kw))
            return R(self.code)
    monkeypatch.delenv("VENDOR_API_KEY", raising=False)
    assert verify.check_source(p, Http(200))["status"] == "missing"                       # no key yet
    monkeypatch.setenv("VENDOR_API_KEY", "fake-key-for-tests-1")
    http = Http(200)
    ok = verify.check_source(p, http)
    assert ok["status"] == "ok" and ok["detail"] == "endpoint answered, key accepted"
    assert http.calls[0][1]["params"] == {"q": "example.com"}                              # asks about example.com, not a client
    assert verify.check_source(p, Http(401))["status"] == "fail"
    assert "fake-key" not in verify.check_source(p, Http(401))["detail"]


@pytest.mark.parametrize("name", ["../evil", "a/b", "Bad", "x", "1abc", "has space", "a" * 60, "", "dns_records"])
def test_bad_or_taken_names_are_refused_and_nothing_is_written(plugin_dir, name, capsys):
    rc = make(plugin_dir, name, "--category", "tech")
    assert rc == 1 and "Not created" in capsys.readouterr().err
    assert not plugin_dir.exists() or not list(plugin_dir.glob("*"))


def test_other_bad_input_is_refused(plugin_dir, capsys):
    assert make(plugin_dir, "ok_name", "--category", "tech", "--needs", "email") == 1               # not a target field
    assert make(plugin_dir, "ok_name", "--category", "tech", "--query", "site:{d} {oops}") == 1      # stray braces
    assert make(plugin_dir, "ok_name", "--tier", "deep", "--category", "tech", "--key-env", "lower") == 1
    with pytest.raises(SystemExit):
        make(plugin_dir, "ok_name", "--category", "nonsense")
    assert not plugin_dir.exists() or not list(plugin_dir.glob("*"))


def test_it_never_overwrites(plugin_dir, capsys):
    assert make(plugin_dir, "once_only", "--category", "tech") == 0
    first = (plugin_dir / "once_only.py").read_text()
    (plugin_dir / "once_only.py").write_text(first + "\n# my edits\n")
    assert make(plugin_dir, "once_only", "--category", "tech") == 1
    assert "my edits" in (plugin_dir / "once_only.py").read_text()


def test_hostile_description_and_query_text_cannot_break_out_of_the_string(plugin_dir):
    nasty = 'x"""\nimport os; os.system("echo pwned")  # \'\'\''
    assert make(plugin_dir, "nasty_text", "--category", "tech", "--description", nasty) == 0
    load_plugins()
    assert REGISTRY["nasty_text"].description == nasty            # carried as data, not executed
    assert "nasty_text.py" not in LOAD_ERRORS
    assert make(plugin_dir, "nasty_query", "--category", "tech", "--query", 'site:{d} "a\\" b\') OR (1') in (0, 1)
    load_plugins()
    assert "nasty_query.py" not in LOAD_ERRORS
