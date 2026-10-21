"""The ROE audit trail: who recorded an authorization, when, and that the history cannot be edited from the app."""
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

from shadowcrumbs import config
from shadowcrumbs.store import Store, clean_person

STAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")


@pytest.fixture
def client():
    from shadowcrumbs.app import app
    return TestClient(app)


def test_creating_an_authorized_engagement_records_who_and_when():
    s = Store.create("A", domain="a.test", auth_ref="SOW-1", authorized=True, authorized_by="Pat Tester")
    [row] = s.authorizations()
    assert (row["action"], row["auth_ref"], row["recorded_by"]) == ("granted", "SOW-1", "Pat Tester")
    assert STAMP.match(row["recorded_at"])
    assert s.meta()["last_authorization"]["recorded_by"] == "Pat Tester"


def test_unauthorized_engagement_has_no_history():
    s = Store.create("A", domain="a.test")
    assert s.authorizations() == [] and s.meta()["last_authorization"] is None


def test_every_change_adds_a_row_and_a_no_op_adds_none():
    s = Store.create("A", domain="a.test")
    s.update_meta(authorized=True, auth_ref="SOW-1", authorized_by="Pat")
    s.update_meta(authorized=True, auth_ref="SOW-1", authorized_by="Someone Else")      # nothing changed
    s.update_meta(auth_ref="SOW-1 rev B", authorized_by="Sam")
    s.update_meta(authorized=False, authorized_by="Pat")
    s.update_meta(notes="just a note")                                                  # not a ROE change
    assert [(r["action"], r["auth_ref"], r["recorded_by"]) for r in s.authorizations()] == [
        ("granted", "SOW-1", "Pat"), ("updated", "SOW-1 rev B", "Sam"), ("revoked", "SOW-1 rev B", "Pat")]


def test_name_is_required_only_when_asked_and_only_for_a_real_change():
    s = Store.create("A", domain="a.test")
    with pytest.raises(ValueError, match="name"):
        s.update_meta(authorized=True, auth_ref="SOW-1", require_name=True)
    assert s.authorizations() == [] and not s.meta()["authorized"]                    # refused, nothing half written
    s.update_meta(authorized=True, auth_ref="SOW-1", authorized_by="Pat", require_name=True)
    s.update_meta(authorized=True, require_name=True)                                  # no change, no name needed
    s.update_meta(authorized=True, auth_ref="SOW-2", authorized_by="Pat")
    assert s.authorizations()[-1]["recorded_by"] == "Pat"
    nameless = Store.create("B", domain="b.test", auth_ref="SOW-9", authorized=True)    # library callers
    assert nameless.authorizations()[0]["recorded_by"] == "unspecified"


def test_names_are_cleaned_to_one_short_line():
    assert clean_person("  Pat\n\tTester\x00 ") == "Pat Tester"
    assert len(clean_person("x" * 500)) == 80


def test_old_database_gets_the_table_and_a_backfilled_row_without_a_made_up_time():
    s = Store.create("Old", domain="old.test", auth_ref="SOW-OLD", authorized=True, authorized_by="Pat")
    c = sqlite3.connect(s.path)                       # rebuild what a database from before the audit trail looks like
    c.execute("DROP TABLE authorizations")
    c.execute("DROP TABLE run_events")
    c.commit()
    c.close()
    again = Store("old")
    [row] = again.authorizations()
    assert row["action"] == "granted" and row["auth_ref"] == "SOW-OLD" and row["recorded_at"] is None
    assert "unknown" in row["recorded_by"]
    assert again.events() == []
    assert len(Store("old").authorizations()) == 1    # opening twice does not backfill twice


def test_api_roundtrip_and_admin_register(client):
    r = client.post("/api/engagements", json={"name": "Acme", "domain": "a.test", "auth_ref": "SOW-1",
                                              "authorized": True, "authorized_by": "Pat Tester"})
    assert r.status_code == 201 and r.json()["last_authorization"]["recorded_by"] == "Pat Tester"
    slug = r.json()["slug"]
    client.patch(f"/api/engagements/{slug}", json={"authorized": False, "authorized_by": "Sam"})
    hist = client.get(f"/api/engagements/{slug}/authorizations").json()
    assert [h["action"] for h in hist] == ["granted", "revoked"]
    reg = client.get("/api/admin/roe").json()
    assert reg[0]["slug"] == slug and reg[0]["authorized"] is False and len(reg[0]["history"]) == 2
    assert client.get("/api/engagements/nope/authorizations").status_code == 404


def test_there_is_no_way_to_edit_or_delete_a_roe_row_over_the_api(client):
    slug = client.post("/api/engagements", json={"name": "A", "domain": "a.test", "auth_ref": "S",
                                                 "authorized": True, "authorized_by": "Pat"}).json()["slug"]
    url = f"/api/engagements/{slug}/authorizations"
    for method in ("put", "patch", "delete", "post"):
        assert getattr(client, method)(url).status_code == 405


def test_roe_changes_and_deletion_reach_the_persistent_app_log(client):
    slug = client.post("/api/engagements", json={"name": "Acme", "domain": "a.test", "auth_ref": "SOW-77",
                                                 "authorized": True, "authorized_by": "Pat Tester"}).json()["slug"]
    assert client.delete(f"/api/engagements/{slug}").status_code == 204
    text = "\n".join(client.get("/api/admin/logs", params={"lines": 100}).json()["lines"])
    assert "ROE granted" in text and "SOW-77" in text and "Pat Tester" in text
    assert "engagement deleted" in text and "granted 'SOW-77' by Pat Tester" in text
    assert (config.logs_dir() / "shadowcrumbs.log").exists()
