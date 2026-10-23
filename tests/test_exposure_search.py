"""exposure_search plugin and the importable source pack."""
import json
from pathlib import Path

from shadowcrumbs import custom_sources
from shadowcrumbs.plugin import Context
from shadowcrumbs.plugins.search_plugins import ExposureSearch
from shadowcrumbs.search import Result

PACK = Path(__file__).resolve().parent.parent / "source_packs" / "exposure_extras.json"


class Canned:
    def __init__(self, table):
        self.table, self.asked = table, []

    def search(self, q, n=20):
        self.asked.append(q)
        return next((v for k, v in self.table.items() if k in q), [])


def run(table, target):
    s = Canned(table)
    return s, list(ExposureSearch().run(Context(target=target, search=s, http=None, store=None)))


def test_finds_each_kind_and_never_keeps_paste_text():
    table = {
        "internal use only": [Result("Q3 plan", "https://www.acme.test/hr/plan.pdf", ""),
                              Result("elsewhere", "https://other.test/x.pdf", ""),
                              Result("page", "https://www.acme.test/about", "")],
        "pastebin.com": [Result("dump", "https://pastebin.com/abc",
                                "bob@acme.test:Hunter2! and eve@other.test")],
        "s3.amazonaws.com": [Result("acme backups", "https://s3.amazonaws.com/acme-backups/x", ""),
                             Result("noise", "https://s3.amazonaws.com/zzz/x", "unrelated")],
    }
    s, found = run(table, {"company": "Acme", "domain": "acme.test"})
    by = {(f.category, f.value): f for f in found}
    assert ("documents", "https://www.acme.test/hr/plan.pdf") in by           # on domain document
    assert not any("other.test" in f.value or f.value.endswith("/about") for f in found)
    mail = by[("emails", "bob@acme.test")]
    assert mail.notes == "Seen on pastebin.com" and "Hunter2" not in repr(found)
    assert ("emails", "eve@other.test") not in by                              # other domain dropped
    assert ("infrastructure", "cloud storage: s3.amazonaws.com/acme-backups") in by
    assert not any("zzz" in f.value for f in found)


def test_company_only_target_runs_only_the_cloud_query():
    s, found = run({}, {"company": "Acme Demo Corp"})
    assert len(s.asked) == 1 and "s3.amazonaws.com" in s.asked[0] and found == []


def test_pack_is_valid_and_imports_cleanly(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOWCRUMBS_SOURCES_FILE", str(tmp_path / "s.json"))
    sources = json.loads(PACK.read_text())["sources"]
    assert sources and all(custom_sources.clean(x) for x in sources)
    out = custom_sources.import_sources(sources, author="Tester")
    assert out["imported"] == len(sources) and out["skipped"] == []


def test_example_addresses_from_format_sites_are_dropped_but_real_ones_stay():
    table = {"email format": [Result("RocketReach", "https://rocketreach.co/acme",
                                     "jane.doe@acme.test jdoe@acme.test first.last@acme.test firstinitiallastname@acme.test "
                                     "customerservice@acme.test priya.nair@acme.test")]}
    _, found = run(table, {"company": "Acme", "domain": "acme.test"})
    got = {f.value for f in found if f.category == "emails"}
    assert got == {"customerservice@acme.test", "priya.nair@acme.test"}


def test_the_targets_own_page_may_list_example_names_but_never_templates():
    table = {"email format": [Result("Contact", "https://www.acme.test/contact", "jane.doe@acme.test first.last@acme.test")]}
    _, found = run(table, {"company": "Acme", "domain": "acme.test"})
    assert {f.value for f in found if f.category == "emails"} == {"jane.doe@acme.test"}


def test_indexed_admin_and_login_pages_land_under_exposures_with_the_full_url():
    table = {
        "inurl:admin": [Result("Admin Login", "https://www.acme.test/admin/login", ""),
                        Result("someone else's admin", "https://other.test/admin", "")],
        "intitle:\"index of\"": [Result("Index of /backups", "https://www.acme.test/backups/", "")],
    }
    _, found = run(table, {"company": "Acme", "domain": "acme.test"})
    exp = {(f.value, f.notes.split("]")[0] + "]") for f in found if f.category == "exposures"}
    assert ("https://www.acme.test/admin/login", "[Admin page]") in exp
    assert ("https://www.acme.test/backups/", "[Open directory listing]") in exp
    assert not any(f.category == "exposures" and "other.test" in f.value for f in found)


def test_a_page_that_only_mentions_the_client_is_not_their_cloud_storage():
    table = {"s3.amazonaws.com": [Result("Retail Management, Acme case study", "https://s3.amazonaws.com/lumenlearning/ch4", "Acme"),
                                  Result("backups", "https://acme-backups.s3.amazonaws.com/db", "")]}
    _, found = run(table, {"company": "Acme", "domain": "acme.test"})
    assert [f.value for f in found if f.category == "infrastructure"] == ["cloud storage: acme-backups.s3.amazonaws.com/db"]
