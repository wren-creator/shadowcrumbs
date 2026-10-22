import json
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from shadowcrumbs.app import app
    return TestClient(app)


def wait_idle(client, slug, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        st = client.get(f"/api/engagements/{slug}/runs").json()["status"]
        if st["state"] == "idle":
            return st
        time.sleep(0.1)
    raise AssertionError("run never finished")


def make(client, **over):
    body = {"name": "Acme Demo", "company": "Acme Demo Corp", "domain": "acme-demo.test", **over}
    r = client.post("/api/engagements", json=body)
    assert r.status_code == 201, r.text
    return r.json()["slug"]


def test_dashboard_and_meta_are_served(client):
    html = client.get("/").text
    assert "SHADOWCRUMBS" in html and "app.js" in html
    assert client.get("/app.js").status_code == 200 and client.get("/style.css").status_code == 200
    meta = client.get("/api/meta").json()
    assert [c["key"] for c in meta["categories"]][:2] == ["employees", "emails"]
    names = {p["name"] for p in meta["plugins"]}
    assert {"subdomains_search", "dns_records", "doc_metadata"} <= names


def test_validation_errors(client):
    assert client.post("/api/engagements", json={"name": "x"}).status_code == 400
    assert client.post("/api/engagements", json={"name": "x", "domain": "bad domain"}).status_code == 400
    assert client.post("/api/engagements", json={"name": "x", "domain": "a.test", "authorized": True}).status_code == 400
    assert client.post("/api/engagements", json={"name": "x", "domain": "a.test", "authorized": True,
                                                 "auth_ref": "SOW-1"}).status_code == 400   # no name of who recorded it
    assert client.get("/api/engagements/nope").status_code == 404
    assert client.get("/api/engagements/..%2Fetc/findings").status_code in (404, 422)


def test_full_flow_search_export_and_gate(client):
    slug = make(client)

    r = client.post(f"/api/engagements/{slug}/runs", json={"tier": "search"})
    assert r.status_code == 202
    st = wait_idle(client, slug)
    assert st["summary"]["new_findings"] > 15 and st["error"] is None

    eng = client.get(f"/api/engagements/{slug}").json()
    assert eng["counts"]["employees"] == 3 and eng["counts"]["subdomains"] >= 4

    emp = client.get(f"/api/engagements/{slug}/findings", params={"category": "employees"}).json()
    assert {f["value"] for f in emp} == {"Jane Doe", "Marcus Webb", "Priya Nair"}
    assert client.get(f"/api/engagements/{slug}/findings", params={"category": "bogus"}).status_code == 400

    # verify, then drop one
    fid = emp[0]["id"]
    assert client.patch(f"/api/engagements/{slug}/findings/{fid}", json={"verified": True}).status_code == 200
    assert client.delete(f"/api/engagements/{slug}/findings/{emp[1]['id']}").status_code == 204
    assert client.delete(f"/api/engagements/{slug}/findings/99999").status_code == 404

    # exports
    md = client.get(f"/api/engagements/{slug}/export", params={"format": "md"})
    assert md.status_code == 200 and "attachment" in md.headers["content-disposition"]
    assert "## Employees" in md.text and "## Run history" in md.text and "No authorization reference" in md.text
    js = client.get(f"/api/engagements/{slug}/export", params={"format": "json"}).json()
    assert js["engagement"]["domain"] == "acme-demo.test" and len(js["findings"]) > 15
    pdf = client.get(f"/api/engagements/{slug}/export", params={"format": "pdf"})
    assert pdf.content.startswith(b"%PDF") and len(pdf.content) > 2000
    assert client.get(f"/api/engagements/{slug}/export", params={"format": "docx"}).status_code == 422

    # deep dive gate, then unlock
    assert client.post(f"/api/engagements/{slug}/runs", json={"tier": "deep"}).status_code == 403
    bad = client.patch(f"/api/engagements/{slug}", json={"authorized": True})
    assert bad.status_code == 400
    nameless = client.patch(f"/api/engagements/{slug}", json={"authorized": True, "auth_ref": "SOW 2026-114"})
    assert nameless.status_code == 400 and "name" in nameless.json()["detail"]
    ok = client.patch(f"/api/engagements/{slug}", json={"authorized": True, "auth_ref": "SOW 2026-114",
                                                        "authorized_by": "Pat Tester"})
    assert ok.status_code == 200 and ok.json()["authorized"] is True
    assert "SOW 2026-114" in client.get(f"/api/engagements/{slug}/export", params={"format": "md"}).text


def test_single_plugin_run_and_unknown_plugin(client):
    slug = make(client)
    assert client.post(f"/api/engagements/{slug}/runs", json={"tier": "search", "plugins": ["nope"]}).status_code == 400
    assert client.post(f"/api/engagements/{slug}/runs", json={"tier": "search", "plugins": ["emails_search"]}).status_code == 202
    wait_idle(client, slug)
    runs = client.get(f"/api/engagements/{slug}/runs").json()["runs"]
    assert [r["plugin"] for r in runs] == ["emails_search"]


def test_tabs_are_isolated_and_delete_works(client):
    a = make(client, name="Client A", domain="acme-demo.test")
    b = make(client, name="Client B", company="Other Co", domain="other-co.test")
    client.post(f"/api/engagements/{a}/runs", json={"tier": "search"})
    wait_idle(client, a)
    assert client.get(f"/api/engagements/{b}/findings").json() == []
    assert len(client.get("/api/engagements").json()) == 2
    assert client.delete(f"/api/engagements/{a}").status_code == 204
    assert [e["slug"] for e in client.get("/api/engagements").json()] == [b]


def test_markdown_export_escapes_table_breakers(client):
    from shadowcrumbs.store import Store
    slug = make(client)
    Store(slug).add_finding("tech", "Weird | value", "t", "search", notes="line one\nline two | pipe")
    md = client.get(f"/api/engagements/{slug}/export", params={"format": "md"}).text
    assert "Weird \\| value" in md and "line one line two \\| pipe" in md


# --- DNS rebinding and cross-site requests ----------------------------------------------

@pytest.mark.parametrize("host", ["evil.example", "attacker.test:8470", "127.0.0.1.evil.example", ""])
def test_unknown_host_header_is_refused(client, host):
    r = client.get("/api/engagements", headers={"Host": host})
    assert r.status_code == 400 and "Host" in r.json()["detail"]


@pytest.mark.parametrize("host", ["127.0.0.1:8470", "localhost:8470", "localhost", "[::1]:8470"])
def test_localhost_names_are_allowed(client, host):
    assert client.get("/api/engagements", headers={"Host": host}).status_code == 200


def test_cross_site_origin_is_refused_even_on_a_good_host(client):
    r = client.post("/api/engagements", headers={"Host": "localhost:8470", "Origin": "https://evil.example"},
                    json={"name": "x", "domain": "x.test"})
    assert r.status_code == 403
    assert client.get("/api/engagements").json() == []            # nothing got created


def test_same_origin_requests_pass(client):
    r = client.post("/api/engagements", headers={"Host": "localhost:8470", "Origin": "http://localhost:8470"},
                    json={"name": "x", "domain": "x.test"})
    assert r.status_code == 201


def test_extra_host_can_be_allowed_by_config(client, monkeypatch):
    monkeypatch.setenv("SHADOWCRUMBS_ALLOWED_HOSTS", "recon.lan")
    assert client.get("/api/engagements", headers={"Host": "recon.lan:8470"}).status_code == 200


def test_scope_domains_only_accept_subdomains_and_need_a_name(client):
    slug = make(client)
    url = f"/api/engagements/{slug}/scope-domains"
    assert client.post(url, json={"domain": "dev.acme-demo.test"}).status_code == 400          # no name
    assert client.post(url, json={"domain": "evil.test", "added_by": "Sam"}).status_code == 400  # not under the domain
    assert client.post(url, json={"domain": "acme-demo.test", "added_by": "Sam"}).status_code == 400
    ok = client.post(url, json={"domain": "https://Dev.acme-demo.test/", "added_by": "Sam"})
    assert ok.status_code == 201 and [d["domain"] for d in ok.json()["scope_domains"]] == ["dev.acme-demo.test"]
    again = client.post(url, json={"domain": "dev.acme-demo.test", "added_by": "Sam"})
    assert len(again.json()["scope_domains"]) == 1
    assert "dev.acme-demo.test" in client.get(f"/api/engagements/{slug}/export", params={"format": "md"}).text
    assert client.delete(f"{url}/dev.acme-demo.test").status_code == 200
    assert client.delete(f"{url}/dev.acme-demo.test").status_code == 404


def test_run_covers_scoped_subdomains_and_refuses_others(client):
    slug = make(client)
    client.post(f"/api/engagements/{slug}/scope-domains", json={"domain": "dev.acme-demo.test", "added_by": "Sam"})
    run = f"/api/engagements/{slug}/runs"
    assert client.post(run, json={"tier": "search", "plugins": ["emails_search"], "domains": ["evil.test"]}).status_code == 400
    both = {"tier": "search", "plugins": ["emails_search"], "domains": ["acme-demo.test", "dev.acme-demo.test"]}
    assert client.post(run, json=both).status_code == 202
    st = wait_idle(client, slug)
    assert st["summary"]["plugins"] and st["summary"]["plugins"][-1]["name"] == "emails_search @ dev.acme-demo.test"
    assert [r["plugin"] for r in client.get(run).json()["runs"]] == ["emails_search @ dev.acme-demo.test", "emails_search"]
