import pytest

from shadowcrumbs import engine
from shadowcrumbs.plugin import REGISTRY, load_plugins
from shadowcrumbs.store import Store
from shadowcrumbs.util import email_format, normalize_domain, normalize_ip

load_plugins()


def vals(store, cat):
    return {f["value"] for f in store.findings(cat)}


# store ---------------------------------------------------------------

def test_create_normalizes_and_validates():
    s = Store.create("X", domain="https://WWW.Acme-Demo.test/path?q=1")
    assert s.meta()["domain"] == "acme-demo.test"
    with pytest.raises(ValueError):
        Store.create("Y")  # no target
    with pytest.raises(ValueError):
        Store.create("Z", domain="not a domain")
    with pytest.raises(ValueError):
        Store.create("W", ip="999.1.1.1")
    assert normalize_ip("10.0.0.5/24") == "10.0.0.0/24"
    assert normalize_domain("") is None


def test_slugs_are_unique_and_safe():
    a = Store.create("Same Name", domain="a.test")
    b = Store.create("Same Name", domain="b.test")
    assert a.slug == "same-name" and b.slug == "same-name-2"
    for bad in ("../etc/passwd", "a/b", "", "UPPER"):
        with pytest.raises(KeyError):
            Store(bad)


def test_authorization_needs_a_reference():
    with pytest.raises(ValueError):
        Store.create("A", domain="a.test", authorized=True)
    s = Store.create("B", domain="b.test")
    with pytest.raises(ValueError):
        s.update_meta(authorized=True)
    s.update_meta(authorized=True, auth_ref="SOW-1")
    assert s.meta()["authorized"] and s.meta()["auth_ref"] == "SOW-1"


def test_findings_dedupe_and_merge_sources(demo):
    assert demo.add_finding("emails", "a@b.test", "p1", "search", confidence=70) is True
    assert demo.add_finding("emails", "a@b.test", "p2", "deep", url="https://x.test") is False
    (f,) = demo.findings("emails")
    assert f["plugins"] == ["p1", "p2"] and f["url"] == "https://x.test"
    with pytest.raises(ValueError):
        demo.add_finding("nope", "x", "p", "search")
    demo.update_finding(f["id"], verified=True, notes="checked")
    assert demo.findings("emails")[0]["verified"] is True
    demo.delete_finding(f["id"])
    assert demo.findings() == []


def test_engagements_are_siloed():
    a = Store.create("Client A", domain="a.test")
    b = Store.create("Client B", domain="b.test")
    a.add_finding("emails", "x@a.test", "p", "search")
    assert b.findings() == [] and len(a.findings()) == 1


def test_email_format_guess():
    assert email_format(["jane.doe@x.test", "john.smith@x.test", "info@x.test"], "x.test")[0] == "first.last"
    assert email_format(["jane@x.test", "john@x.test"], "x.test") is None


# search tier -----------------------------------------------------------

def test_search_tier_end_to_end(demo):
    summary = engine.execute(demo.slug, "search")
    assert [p["status"] for p in summary["plugins"]] == ["ok"] * 5

    subs = vals(demo, "subdomains")
    assert {"portal.acme-demo.test", "vpn.acme-demo.test", "mail.acme-demo.test", "files.acme-demo.test"} <= subs

    docs = vals(demo, "documents")
    assert "https://www.acme-demo.test/docs/network-overview.pdf" in docs
    assert "https://files.acme-demo.test/reports/Q3-ops.xlsx" in docs
    assert not any(d.endswith("/about") for d in docs)

    emails = vals(demo, "emails")
    assert {"jane.doe@acme-demo.test", "john.smith@acme-demo.test", "mary.jones@acme-demo.test",
            "raj.patel@acme-demo.test"} <= emails
    assert "format: first.last@acme-demo.test" in emails

    people = vals(demo, "employees")
    assert people == {"Jane Doe", "Marcus Webb", "Priya Nair"}  # CISSP stripped, other company dropped

    tech = vals(demo, "tech")
    for want in ("IBM i (AS/400)", "z/OS mainframe", "RACF", "Siemens SIMATIC and S7", "Rockwell and Allen-Bradley",
                 "Palo Alto Networks", "z/TPF"):
        assert want in tech, want


def test_second_run_uses_cache_and_adds_nothing(demo):
    first = engine.execute(demo.slug, "search")
    second = engine.execute(demo.slug, "search")
    assert first["searches_live"] > 0
    assert second["searches_live"] == 0 and second["searches_cached"] > 0
    assert second["new_findings"] == 0


def test_domain_only_plugins_skip_cleanly():
    s = Store.create("Company only", company="Acme Demo Corp")
    summary = engine.execute(s.slug, "search")
    by = {p["name"]: p for p in summary["plugins"]}
    assert by["subdomains_search"]["status"] == "skipped"
    assert by["employees_search"]["status"] == "ok"


# gating and failure handling ----------------------------------------------

def test_deep_dive_is_locked_until_authorized(demo):
    with pytest.raises(PermissionError):
        engine.execute(demo.slug, "deep")
    with pytest.raises(PermissionError):
        engine.start(demo.slug, "deep")


def test_one_bad_plugin_does_not_stop_the_run(demo):
    from shadowcrumbs.plugin import Plugin, register

    @register
    class Boom(Plugin):
        name = "boom_test"
        tier = "search"
        order = 1
        needs_any = ("domain",)

        def run(self, ctx):
            yield from ()
            raise RuntimeError("kaput")

    try:
        summary = engine.execute(demo.slug, "search")
    finally:
        REGISTRY.pop("boom_test")
    by = {p["name"]: p for p in summary["plugins"]}
    assert by["boom_test"]["status"] == "error" and "kaput" in by["boom_test"]["error"]
    assert by["subdomains_search"]["status"] == "ok"
    assert any(r["plugin"] == "boom_test" and r["status"] == "error" for r in demo.runs())


def test_unknown_plugin_name_rejected(demo):
    with pytest.raises(ValueError):
        engine.select("search", ["nope"])
    with pytest.raises(ValueError):
        engine.select("search", ["dns_records"])  # that one is deep tier


def test_user_plugin_loader(tmp_path, monkeypatch):
    d = tmp_path / "plugins_user"
    d.mkdir()
    (d / "hello.py").write_text(
        "from shadowcrumbs.plugin import Plugin, Finding, register\n"
        "@register\n"
        "class Hello(Plugin):\n"
        "    name='hello_user'\n    tier='search'\n"
        "    def run(self, ctx):\n        yield Finding('tech', 'Hello', confidence=1)\n"
    )
    (d / "broken.py").write_text("raise SyntaxError('nope')\n")
    (d / "_skipped.py").write_text("raise RuntimeError('never loaded')\n")
    from shadowcrumbs.plugin import LOAD_ERRORS
    load_plugins()
    try:
        assert "hello_user" in REGISTRY
        assert "broken.py" in LOAD_ERRORS and "_skipped.py" not in LOAD_ERRORS
    finally:
        REGISTRY.pop("hello_user", None)


def test_personal_plugin_folder_loads_alongside_the_normal_one(tmp_path, monkeypatch):
    from shadowcrumbs import plugin
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "private_thing.py").write_text(
        "from shadowcrumbs.plugin import Plugin, register\n"
        "@register\nclass PrivateThing(Plugin):\n    name = 'private_thing_test'\n    tier = 'search'\n"
        "    def run(self, ctx):\n        return iter(())\n"
    )
    monkeypatch.setenv("SHADOWCRUMBS_PERSONAL_PLUGINS", str(mine))
    plugin.load_plugins()
    assert "private_thing_test" in plugin.REGISTRY
    plugin.REGISTRY.pop("private_thing_test")
