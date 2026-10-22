"""Custom search sources made from the dashboard: data in, findings out, and nothing a teammate types can run as code."""
import json
import os

import pytest
from fastapi.testclient import TestClient

from shadowcrumbs import config, custom_sources as cs, engine
from shadowcrumbs.plugin import REGISTRY
from shadowcrumbs.store import Store


@pytest.fixture(autouse=True)
def clean_registry():
    cs.sync()
    yield
    for n in [n for n, p in list(REGISTRY.items()) if p.custom]:
        REGISTRY.pop(n)


@pytest.fixture
def client():
    from shadowcrumbs.app import app
    return TestClient(app)


def good(**over):
    base = {"label": "Site pages", "description": "Pages on the domain.", "category": "tech", "needs": ["domain"],
            "queries": ["site:{domain}"], "keywords": [], "only_on_domain": False, "extractor": "title",
            "confidence": 55, "author": "Pat Tester"}
    return {**base, **over}


# validation ---------------------------------------------------------------------------------------

def test_a_good_definition_is_accepted_and_normalized():
    d = cs.clean(good(label="  Site pages  ", keywords=["  Careers ", ""], queries=[" site:{domain} ", ""]))
    assert d["label"] == "Site pages" and d["keywords"] == ["careers"] and d["queries"] == ["site:{domain}"]
    assert d["needs"] == ["domain"] and d["confidence"] == 55 and d["author"] == "Pat Tester"


@pytest.mark.parametrize("over, reason", [
    ({"label": ""}, "name"), ({"label": "x" * 61}, "too long"), ({"label": "a\nb"}, "line breaks"),
    ({"category": "nonsense"}, "file the findings"), ({"category": None}, "file the findings"),
    ({"needs": []}, "pick what it needs"), ({"needs": ["ip"]}, "pick what it needs"), ({"needs": ["domain", "ip"]}, "pick what it needs"),
    ({"needs": "domain"}, "pick what it needs"),
    ({"queries": []}, "at least one"), ({"queries": ["  "]}, "at least one"), ({"queries": "site:x"}, "must be a list"),
    ({"queries": [f"site:{{domain}} {i}" for i in range(11)]}, "at most 10"),
    ({"queries": ["x" * 301]}, "too long"), ({"queries": ["site:{domain}\nsite:evil"]}, "line breaks"),
    ({"queries": ["site:{oops}"]}, "placeholders"), ({"queries": ["{domain"]}, "placeholders"),
    ({"queries": ["\"{company}\" jobs"]}, "does not need the company"),
    ({"keywords": ["k"] * 11}, "at most 10"), ({"extractor": "regex"}, "record each result"),
    ({"extractor": "email", "needs": ["company"], "queries": ["\"{company}\""]}, "needs the domain"),
    ({"only_on_domain": True, "needs": ["company"], "queries": ["\"{company}\""]}, "needs the domain"),
    ({"confidence": 101}, "0 to 100"), ({"confidence": "high"}, "0 to 100"),
    ({"author": ""}, "your name"), ({"description": "x" * 201}, "too long"),
])
def test_bad_definitions_are_refused_with_a_plain_reason(over, reason):
    with pytest.raises(ValueError, match=reason):
        cs.clean(good(**over))


def test_author_can_be_skipped_only_for_a_preview():
    assert cs.clean(good(author=""), require_author=False)["author"] == ""


def test_the_d_alias_still_works_so_template_queries_carry_over():
    assert cs.clean(good(queries=["site:{d} careers"]))["queries"] == ["site:{d} careers"]


# rendering ----------------------------------------------------------------------------------------

def test_queries_are_filled_in_and_the_ones_that_cannot_be_are_reported():
    d = cs.clean(good(needs=["domain", "company"], queries=["site:{domain} jobs", '"{company}" jobs', "no placeholders"]))
    out, dropped = cs.render_queries(d, {"domain": "acme.test", "company": "Acme Corp"})
    assert out == ["site:acme.test jobs", '"Acme Corp" jobs', "no placeholders"] and dropped == []
    out, dropped = cs.render_queries(d, {"domain": "acme.test", "company": None})
    assert out == ["site:acme.test jobs", "no placeholders"]
    assert dropped == [{"query": '"{company}" jobs', "reason": "this target has no company"}]


def test_a_quote_in_the_company_name_cannot_break_out_of_the_phrase():
    d = cs.clean(good(needs=["company"], queries=['"{company}" filetype:pdf']))
    [q], _ = cs.render_queries(d, {"company": 'Acme" OR site:evil.test "x'})
    assert q.count('"') == 2 and q.startswith('"Acme OR site:evil.test x"')


def test_placeholders_are_plain_replacement_not_formatting():
    d = cs.clean(good(queries=["site:{domain}"]))
    [q], _ = cs.render_queries(d, {"domain": "{0.__class__}"})
    assert q == "site:{0.__class__}"                       # inserted as text, never evaluated


# running ------------------------------------------------------------------------------------------

def run_source(demo, **over):
    entry = cs.create(good(**over))
    name = cs.PREFIX + entry["slug"]
    demo.update_meta(authorized=False)
    out = engine.execute(demo.slug, "search", [name])
    return name, out["plugins"][0], demo


def test_title_extractor_files_findings_under_the_chosen_category(demo):
    name, res, demo = run_source(demo, category="infrastructure")
    assert res["status"] == "ok" and res["found"] >= 5
    rows = [f for f in demo.findings("infrastructure") if name in f["plugins"]]
    assert rows and all(r["url"] and r["confidence"] == 55 for r in rows)


def test_hostname_extractor_keeps_only_hosts_on_the_domain(demo):
    name, res, demo = run_source(demo, category="subdomains", extractor="hostname", queries=["site:{domain}", '"@{domain}"'])
    values = {f["value"] for f in demo.findings("subdomains") if name in f["plugins"]}
    assert {"portal.acme-demo.test", "vpn.acme-demo.test"} <= values
    assert all(v.endswith("acme-demo.test") for v in values) and "directory.example.org" not in values


def test_email_extractor_finds_addresses_at_the_domain_only(demo):
    name, res, demo = run_source(demo, category="emails", extractor="email", queries=['"@{domain}"'])
    values = {f["value"] for f in demo.findings("emails") if name in f["plugins"]}
    assert {"jane.doe@acme-demo.test", "john.smith@acme-demo.test"} <= values
    assert all(v.endswith("@acme-demo.test") for v in values)


def test_document_extractor_keeps_document_links_only(demo):
    name, res, demo = run_source(demo, category="documents", extractor="document")
    values = {f["value"] for f in demo.findings("documents") if name in f["plugins"]}
    assert values == {"https://www.acme-demo.test/docs/network-overview.pdf", "https://files.acme-demo.test/reports/Q3-ops.xlsx"}


def test_keyword_filter_and_domain_filter(demo):
    name, res, demo = run_source(demo, keywords=["OWA", "network overview"], queries=["site:{domain}"])
    urls = {f["url"] for f in demo.findings("tech") if name in f["plugins"]}
    assert urls == {"https://mail.acme-demo.test/owa/auth/logon.aspx", "https://www.acme-demo.test/docs/network-overview.pdf"}   # case blind

    off = run_source(demo, label="Anywhere", keywords=["acme"], queries=['"@{domain}"'])[0]
    urls = {f["url"] for f in demo.findings("tech") if off in f["plugins"]}
    assert "https://directory.example.org/acme" in urls                                    # an off-domain result got through...
    on = run_source(demo, label="Only theirs", keywords=["acme"], queries=['"@{domain}"'], only_on_domain=True)[0]
    urls = {f["url"] for f in demo.findings("tech") if on in f["plugins"]}
    assert urls and all("acme-demo.test" in u for u in urls)                               # ...until the domain filter is on


def test_a_source_that_needs_both_fields_is_skipped_with_an_honest_reason(demo):
    entry = cs.create(good(needs=["domain", "company"], queries=['"{company}" site:{domain}']))
    nocompany = Store.create("NoCo", domain="acme-demo.test")
    res = engine.execute(nocompany.slug, "search", [cs.PREFIX + entry["slug"]])["plugins"][0]
    assert res["status"] == "skipped" and res["error"] == "needs domain and company"


# hot reload, naming, the file ---------------------------------------------------------------------

def test_create_edit_delete_through_the_api_are_live_without_a_restart(client):
    r = client.post("/api/custom-sources", json=good())
    assert r.status_code == 201 and r.json()["plugin"] == "custom_site_pages"
    plugins = {p["name"]: p for p in client.get("/api/meta").json()["plugins"]}
    assert plugins["custom_site_pages"]["custom"] is True and plugins["custom_site_pages"]["author"] == "Pat Tester"
    assert plugins["dns_records"]["custom"] is False

    r = client.put("/api/custom-sources/site_pages", json=good(description="Changed.", author="Sam"))
    assert r.status_code == 200
    plugins = {p["name"]: p for p in client.get("/api/meta").json()["plugins"]}
    assert plugins["custom_site_pages"]["description"] == "Changed." and plugins["custom_site_pages"]["author"] == "Sam"
    assert r.json()["created_at"] and r.json()["updated_at"]

    assert client.delete("/api/custom-sources/site_pages", params={"author": "Sam"}).status_code == 204
    assert "custom_site_pages" not in {p["name"] for p in client.get("/api/meta").json()["plugins"]}
    assert client.delete("/api/custom-sources/site_pages", params={"author": "Sam"}).status_code == 404


def test_validation_errors_come_back_as_400_and_nothing_is_saved(client):
    r = client.post("/api/custom-sources", json=good(queries=["site:{oops}"]))
    assert r.status_code == 400 and "placeholders" in r.json()["detail"]
    assert client.post("/api/custom-sources", json=good(author="")).status_code == 400
    assert client.delete("/api/custom-sources/anything").status_code == 400                   # no name
    assert client.get("/api/custom-sources").json()["sources"] == []


def test_same_label_twice_gets_a_distinct_name_and_cannot_shadow_a_built_in(client):
    a = client.post("/api/custom-sources", json=good()).json()
    b = client.post("/api/custom-sources", json=good()).json()
    assert (a["plugin"], b["plugin"]) == ("custom_site_pages", "custom_site_pages_2")
    c = client.post("/api/custom-sources", json=good(label="DNS records")).json()
    assert c["plugin"] == "custom_dns_records" and "dns_records" in REGISTRY and not REGISTRY["dns_records"].custom
    assert client.post("/api/custom-sources", json=good(label="1 weird / name!!")).json()["plugin"].startswith("custom_s_1")


def test_every_change_is_logged_with_who_did_it(client):
    client.post("/api/custom-sources", json=good())
    client.delete("/api/custom-sources/site_pages", params={"author": "Sam"})
    text = "\n".join(client.get("/api/admin/logs", params={"lines": 50}).json()["lines"])
    assert "custom source created: custom_site_pages by 'Pat Tester'" in text
    assert "custom source deleted: custom_site_pages by 'Sam'" in text


def test_a_stale_page_gets_a_conflict_not_a_silent_overwrite(client):
    rev0 = client.get("/api/custom-sources").json()["revision"]
    ok = client.post("/api/custom-sources", json=good(expected_revision=rev0))
    assert ok.status_code == 201
    stale = client.post("/api/custom-sources", json=good(label="Other", expected_revision=rev0))
    assert stale.status_code == 409 and "Someone else changed" in stale.json()["detail"]
    assert client.put("/api/custom-sources/site_pages", json=good(expected_revision=rev0)).status_code == 409
    assert client.delete("/api/custom-sources/site_pages", params={"author": "x", "expected_revision": rev0}).status_code == 409
    fresh = client.get("/api/custom-sources").json()["revision"]
    assert fresh == rev0 + 1 and len(client.get("/api/custom-sources").json()["sources"]) == 1


def test_the_file_path_can_be_moved_for_a_shared_folder(tmp_path, monkeypatch, client):
    shared = tmp_path / "team" / "sources.json"
    monkeypatch.setenv("SHADOWCRUMBS_SOURCES_FILE", str(shared))
    client.post("/api/custom-sources", json=good())
    assert shared.exists() and json.loads(shared.read_text())["sources"][0]["label"] == "Site pages"
    assert not (config.data_dir() / "custom_sources.json").exists()


def test_the_write_is_atomic_and_leaves_no_temp_files(tmp_path, monkeypatch, client):
    seen = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (seen.append((os.path.dirname(a), os.path.dirname(b))), real(a, b))[1])
    client.post("/api/custom-sources", json=good())
    assert seen and all(a == b for a, b in seen)                                        # same folder, so same filesystem
    assert [p.name for p in config.data_dir().iterdir() if p.name.endswith(".tmp")] == []


def test_a_damaged_file_does_not_take_the_app_down_and_is_never_overwritten(client):
    path = config.sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ this is not json")
    cs.sync()
    snap = client.get("/api/custom-sources").json()
    assert snap["sources"] == [] and "could not be read" in snap["problems"][0]
    assert client.get("/api/meta").status_code == 200
    r = client.post("/api/custom-sources", json=good())
    assert r.status_code == 400 and "could not be read" in r.json()["detail"]
    assert path.read_text() == "{ this is not json"                                     # a teammate's file, left alone


def test_one_bad_entry_is_skipped_reported_and_kept_while_the_rest_load(client):
    path = config.sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    keep = {"slug": "ok_one", **good(label="OK one")}
    broken = {"slug": "broken", "label": "Broken", "category": "tech", "needs": ["domain"], "queries": ["{nope}"], "author": "x"}
    path.write_text(json.dumps({"version": 1, "revision": 3, "sources": [keep, broken, "garbage"]}))
    cs.sync()
    snap = client.get("/api/custom-sources").json()
    assert [s["slug"] for s in snap["sources"]] == ["ok_one"] and len(snap["problems"]) == 2
    assert "custom_ok_one" in REGISTRY and "custom_broken" not in REGISTRY
    client.post("/api/custom-sources", json=good(label="Added later"))
    on_disk = json.loads(path.read_text())["sources"]
    assert len(on_disk) == 4 and any(s == "garbage" for s in on_disk) and any(s.get("slug") == "broken" for s in on_disk if isinstance(s, dict))


def test_hand_edited_entries_get_the_same_checks_as_the_form(client):
    path = config.sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    evil = {"slug": "../../etc", **good(label="Evil")}
    path.write_text(json.dumps({"revision": 1, "sources": [evil]}))
    cs.sync()
    assert client.get("/api/custom-sources").json()["sources"] == [] and "custom_../../etc" not in REGISTRY


# preview, export, import --------------------------------------------------------------------------

def test_preview_shows_the_searches_without_touching_the_network_or_the_file(client, demo, monkeypatch):
    monkeypatch.setattr(engine.SearchClient, "search", lambda *a, **k: pytest.fail("preview must not search"))
    r = client.post("/api/custom-sources/preview", json=good(author="", needs=["domain", "company"],
                                                             queries=["site:{domain}", '"{company}" jobs'], engagement=demo.slug))
    assert r.status_code == 200
    assert r.json()["queries"] == ["site:acme-demo.test", '"Acme Demo Corp" jobs'] and r.json()["seconds"] == 0     # delay is 0 in tests
    bare = client.post("/api/custom-sources/preview", json=good(author="", queries=["site:{domain}"]))
    assert bare.json()["queries"] == [] and bare.json()["dropped"][0]["reason"] == "this target has no domain"
    assert client.post("/api/custom-sources/preview", json=good(queries=["{bad}"])).status_code == 400
    assert not config.sources_file().exists()


def test_export_then_import_on_another_machine_round_trips(client, tmp_path, monkeypatch):
    client.post("/api/custom-sources", json=good())
    client.post("/api/custom-sources", json=good(label="Mail", extractor="email", category="emails", queries=['"@{domain}"']))
    dump = client.get("/api/custom-sources/export")
    assert dump.headers["content-disposition"].startswith("attachment") and dump.status_code == 200
    exported = dump.json()
    assert [s["label"] for s in exported["sources"]] == ["Site pages", "Mail"] and "slug" not in exported["sources"][0]

    monkeypatch.setenv("SHADOWCRUMBS_SOURCES_FILE", str(tmp_path / "other.json"))
    cs.sync()
    r = client.post("/api/custom-sources/import", json={"sources": exported["sources"], "author": "New Teammate"})
    assert r.json()["imported"] == 2 and r.json()["skipped"] == []
    names = {p["name"] for p in client.get("/api/meta").json()["plugins"] if p["custom"]}
    assert names == {"custom_site_pages", "custom_mail"}
    assert {p["author"] for p in client.get("/api/meta").json()["plugins"] if p["custom"]} == {"Pat Tester"}    # original author kept


def test_import_modes_for_a_name_you_already_have(client):
    client.post("/api/custom-sources", json=good())
    new = [good(description="The newer one", author="Sam")]
    skip = client.post("/api/custom-sources/import", json={"sources": new, "author": "Sam"}).json()
    assert skip["imported"] == 0 and "already have" in skip["skipped"][0]["reason"]
    over = client.post("/api/custom-sources/import", json={"sources": new, "mode": "overwrite", "author": "Sam"}).json()
    assert over["imported"] == 1
    srcs = client.get("/api/custom-sources").json()["sources"]
    assert len(srcs) == 1 and srcs[0]["description"] == "The newer one" and srcs[0]["slug"] == "site_pages"
    ren = client.post("/api/custom-sources/import", json={"sources": new, "mode": "rename", "author": "Sam"}).json()
    assert ren["imported"] == 1
    assert sorted(s["label"] for s in client.get("/api/custom-sources").json()["sources"]) == ["Site pages", "Site pages (2)"]


def test_import_checks_every_entry_and_reports_the_ones_it_skips(client):
    hostile = [good(label="Fine"), good(label="Bad placeholder", queries=["{x}"]), "a string", {"label": "Nothing else"},
               good(label="Fine too", extractor="eval")]
    r = client.post("/api/custom-sources/import", json={"sources": [h for h in hostile if isinstance(h, dict)], "author": "Sam"}).json()
    assert r["imported"] == 1 and len(r["skipped"]) == 3
    assert {s["label"] for s in r["skipped"]} == {"Bad placeholder", "Nothing else", "Fine too"}
    assert client.post("/api/custom-sources/import", json={"sources": [], "author": ""}).status_code == 400
    assert client.post("/api/custom-sources/import", json={"sources": [], "mode": "yolo", "author": "x"}).status_code == 422


def test_nothing_in_a_definition_is_ever_executed(demo):
    nasty = good(label="__import__('os').system('echo pwned')", description="${jndi:ldap://x} {{7*7}} <script>",
                 queries=["site:{domain} `id` $(id) ; rm -rf / '\" OR 1=1"], keywords=["__import__"])
    entry = cs.create(nasty)
    res = engine.execute(demo.slug, "search", [cs.PREFIX + entry["slug"]])["plugins"][0]
    assert res["status"] == "ok"
    assert cs.PREFIX + entry["slug"] in REGISTRY
