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
