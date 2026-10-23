import io
import zipfile

import pytest

from shadowcrumbs import engine
from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import deep_plugins as dp
from shadowcrumbs.store import Store

load_plugins()


class FakeHttp:
    def __init__(self, json_map=None, files=None, probes=None):
        self.json_map, self.files, self.probes = json_map or {}, files or {}, probes or {}
        self.downloads = []

    def get_json(self, url, timeout=None):
        for prefix, data in self.json_map.items():
            if url.startswith(prefix):
                return data
        return None

    def download(self, url, max_bytes=None):
        self.downloads.append(url)
        return self.files[url]

    def probe(self, host):
        return self.probes.get(host)

    def get(self, url, **kw):
        """Plain GETs (urlscan.io, say) answer with an empty result set unless a test says otherwise."""
        class Empty:
            status_code, headers = 200, {}
            def json(self): return {"results": []}
            def raise_for_status(self): pass
            def iter_content(self, n): return iter(())
            def close(self): pass
        return Empty()


@pytest.fixture
def store():
    return Store.create("Deep", company="Acme Demo Corp", domain="acme-demo.test", ip="203.0.113.0/28")


def run(name, store, http=None):
    meta = store.meta()
    ctx = Context(target={k: meta[k] for k in ("company", "domain", "ip")}, search=None,
                  http=http or FakeHttp(), store=store)
    return list(REGISTRY[name].run(ctx))


def stub_dns(monkeypatch, table):
    monkeypatch.setattr(dp, "dns_lookup", lambda name, rtype: table.get((name, rtype), ([], "empty")))


def test_dns_records_and_mail_posture(store, monkeypatch):
    stub_dns(monkeypatch, {
        ("acme-demo.test", "A"): (["203.0.113.10"], "ok"),
        ("acme-demo.test", "MX"): (["10 mx1.mail.test."], "ok"),
        ("acme-demo.test", "TXT"): (['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=abc"'], "ok"),
    })
    out = {f.value: f for f in run("dns_records", store)}
    assert "A 203.0.113.10" in out and "MX 10 mx1.mail.test" in out
    spf = next(f for v, f in out.items() if v.startswith("SPF:"))
    assert "Soft fail" in spf.notes
    assert "DMARC record missing" in out
    assert any(v.startswith("TXT: google-site-verification") for v in out)


def test_dmarc_monitor_only_is_called_out(store, monkeypatch):
    stub_dns(monkeypatch, {
        ("acme-demo.test", "TXT"): (['"v=spf1 -all"'], "ok"),
        ("_dmarc.acme-demo.test", "TXT"): (['"v=DMARC1; p=none; rua=mailto:x@acme-demo.test"'], "ok"),
    })
    out = {f.value: f for f in run("dns_records", store)}
    dmarc = next(f for v, f in out.items() if v.startswith("DMARC:"))
    assert "monitor only" in dmarc.notes and "SPF record missing" not in out


def test_rdap_domain_and_cidr(store):
    http = FakeHttp({
        "https://rdap.org/domain/acme-demo.test": {
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]]}],
            "nameservers": [{"ldhName": "NS1.ACME-DEMO.TEST"}],
            "events": [{"eventAction": "registration", "eventDate": "2001-04-05T00:00:00Z"}],
        },
        "https://rdap.org/ip/203.0.113.0": {"startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                                             "name": "DOC-NET", "handle": "NET-1", "country": "US"},
    })
    out = {f.value for f in run("rdap", store, http)}
    assert {"Registrar: Example Registrar Inc", "NS ns1.acme-demo.test", "Domain registration: 2001-04-05",
            "Netblock 203.0.113.0 to 203.0.113.255"} <= out


def test_rdap_walks_up_from_a_subdomain_to_the_registered_domain():
    import requests
    store = Store.create("Sub", company="Acme Demo Corp", domain="scan.corp.acme-demo.test")

    bad = requests.Response()
    bad.status_code = 400

    class Http(FakeHttp):
        def get_json(self, url, timeout=None):
            self.seen = getattr(self, "seen", []) + [url]
            if url.endswith("/scan.corp.acme-demo.test"):
                raise requests.HTTPError("400", response=bad)
            if url.endswith("/corp.acme-demo.test"):
                return None
            if url.endswith("/acme-demo.test"):
                return {"nameservers": [{"ldhName": "NS1.ACME-DEMO.TEST"}]}
            return None

    http = Http()
    out = {f.value for f in run("rdap", store, http)}
    assert "NS ns1.acme-demo.test" in out
    assert [u.rsplit("/", 1)[1] for u in http.seen[:3]] == ["scan.corp.acme-demo.test", "corp.acme-demo.test", "acme-demo.test"]


def test_crtsh_dedupes_and_stays_in_scope(store):
    http = FakeHttp({"https://crt.sh/": [
        {"name_value": "*.acme-demo.test\nvpn.acme-demo.test", "issuer_name": "Let's Encrypt"},
        {"name_value": "vpn.acme-demo.test\ndev.acme-demo.test\nevil.example.org", "issuer_name": "Other"},
        {"name_value": "acme-demo.test"},
    ]})
    assert {f.value for f in run("crtsh", store, http)} == {"vpn.acme-demo.test", "dev.acme-demo.test"}


def test_takeover_detection(store, monkeypatch):
    store.add_finding("subdomains", "old.acme-demo.test", "t", "search")
    store.add_finding("subdomains", "ok.acme-demo.test", "t", "search")
    stub_dns(monkeypatch, {
        ("old.acme-demo.test", "CNAME"): (["acme-old.github.io."], "ok"),
        ("acme-old.github.io", "A"): ([], "nxdomain"),
        ("ok.acme-demo.test", "A"): (["203.0.113.7"], "ok"),
    })
    out = {f.value for f in run("resolve_subdomains", store)}
    assert "Possible subdomain takeover: old.acme-demo.test" in out
    assert "ok.acme-demo.test A 203.0.113.7" in out


def test_http_probe_headers_and_banners(store):
    store.add_finding("subdomains", "vpn.acme-demo.test", "t", "search")
    http = FakeHttp(probes={
        "acme-demo.test": {"scheme": "https", "status": 200, "final_url": "https://acme-demo.test/",
                           "server": "Apache/2.4.29 (Ubuntu)", "powered_by": None, "aspnet": None, "title": "Acme"},
        "vpn.acme-demo.test": {"scheme": "https", "status": 200, "final_url": "https://vpn.acme-demo.test/",
                               "server": None, "powered_by": "ASP.NET", "aspnet": "4.0.30319",
                               "title": "Citrix Gateway"},
    })
    out = {(f.category, f.value) for f in run("http_probe", store, http)}
    assert ("tech", "Server: Apache/2.4.29 (Ubuntu)") in out
    assert ("tech", "X-AspNet-Version: 4.0.30319") in out
    assert ("tech", "Citrix") in out
    assert ("infrastructure", "vpn.acme-demo.test responds 200 over https") in out


class PathResp:
    def __init__(self, status=404, body=b""):
        self.status_code, self._body = status, body

    def iter_content(self, n):
        return iter([self._body]) if self._body else iter(())

    def close(self):
        pass


def test_exposure_probe_reports_full_urls_classified_by_what_they_expose(store):
    store.add_finding("subdomains", "admin.acme-demo.test", "t", "search")

    class Http(FakeHttp):
        def probe(self, host):
            return {"scheme": "https"}      # every host answers, so paths are tried against both

        def get(self, url, **kw):
            answers = {
                "https://acme-demo.test/.git/config": PathResp(200, b"[core]\n\trepositoryformatversion"),
                "https://acme-demo.test/backup.sql": PathResp(200, b"-- MySQL dump"),
                "https://admin.acme-demo.test/admin/": PathResp(200, b"<html><body>Welcome</body></html>"),  # a custom 404 page
            }
            return answers.get(url, PathResp(404))

    out = {(f.category, f.value): f for f in run("exposure_probe", store, Http())}
    assert out[("exposures", "https://acme-demo.test/.git/config")].notes.startswith("[Exposed source control]")
    assert out[("exposures", "https://acme-demo.test/backup.sql")].notes.startswith("[Exposed backup]")
    # a 200 that is really a generic HTML page, not the file itself, is noise and must not be reported
    assert ("exposures", "https://admin.acme-demo.test/admin/") not in out


def test_exposure_probe_skips_a_host_that_answers_nothing(store):
    class Http(FakeHttp):
        def probe(self, host):
            return None

    assert run("exposure_probe", store, Http()) == []


def make_docx(creator="Dana Smith", last="dsmith", app="Microsoft Office Word", ver="16.0000"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml",
                   '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                   'xmlns:dc="http://purl.org/dc/elements/1.1/">'
                   f"<dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{last}</cp:lastModifiedBy></cp:coreProperties>")
        z.writestr("docProps/app.xml",
                   '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                   f"<Application>{app}</Application><AppVersion>{ver}</AppVersion><Company>Acme Demo</Company></Properties>")
    return buf.getvalue()


def make_pdf():
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.setAuthor("Pat Lee")
    c.setCreator("Acrobat PDFMaker 11")
    c.drawString(72, 720, "hello")
    c.save()
    return buf.getvalue()


def test_doc_metadata_reads_authors_and_software(store):
    store.add_finding("documents", "https://www.acme-demo.test/a.docx", "t", "search")
    store.add_finding("documents", "https://www.acme-demo.test/b.pdf", "t", "search")
    store.add_finding("documents", "https://elsewhere.example.org/c.pdf", "t", "search")  # off domain
    http = FakeHttp(files={
        "https://www.acme-demo.test/a.docx": make_docx(),
        "https://www.acme-demo.test/b.pdf": make_pdf(),
    })
    out = {(f.category, f.value) for f in run("doc_metadata", store, http)}
    assert ("employees", "Dana Smith") in out and ("employees", "dsmith") in out
    assert ("employees", "Pat Lee") in out
    assert ("tech", "Document software: Microsoft Office Word 16.0000") in out
    assert ("tech", "Document software: Acrobat PDFMaker 11") in out
    assert "https://elsewhere.example.org/c.pdf" not in http.downloads


def test_doc_metadata_survives_hostile_and_broken_files(store):
    store.add_finding("documents", "https://www.acme-demo.test/bomb.docx", "t", "search")
    store.add_finding("documents", "https://www.acme-demo.test/junk.docx", "t", "search")
    store.add_finding("documents", "https://www.acme-demo.test/good.docx", "t", "search")
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w") as z:
        z.writestr("docProps/core.xml",
                   '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><x>&b;</x>')
    http = FakeHttp(files={
        "https://www.acme-demo.test/bomb.docx": bomb.getvalue(),
        "https://www.acme-demo.test/junk.docx": b"PK not really a zip",
        "https://www.acme-demo.test/good.docx": make_docx(creator="Real Person"),
    })
    out = {f.value for f in run("doc_metadata", store, http)}
    assert "Real Person" in out


def test_generic_authors_are_dropped():
    assert dp._clean_author("Microsoft Office User") is None
    assert dp._clean_author("x" * 80) is None
    assert dp._clean_author(" Dana Smith ") == "Dana Smith"


def test_full_deep_run_through_engine(store, monkeypatch):
    store.update_meta(authorized=True, auth_ref="SOW-42")
    store.add_finding("subdomains", "vpn.acme-demo.test", "t", "search")
    stub_dns(monkeypatch, {("acme-demo.test", "A"): (["203.0.113.10"], "ok")})
    monkeypatch.setattr(engine, "HttpClient", lambda: FakeHttp(
        json_map={"https://rdap.org/domain/": {"nameservers": [{"ldhName": "ns1.acme-demo.test"}]}},
        probes={"acme-demo.test": {"scheme": "https", "status": 200, "final_url": "https://acme-demo.test/",
                                   "server": "nginx", "powered_by": None, "aspnet": None, "title": None}},
    ))
    summary = engine.execute(store.slug, "deep")
    by = {p["name"]: p["status"] for p in summary["plugins"]}
    assert by["dns_records"] == "ok" and by["rdap"] == "ok" and by["http_probe"] == "ok"
    assert all(s in ("ok", "skipped") for s in by.values()), by
    assert ("tech", "Server: nginx") in {(f["category"], f["value"]) for f in store.findings()}


# doc_content: what is written inside the files ---------------------------------------------------------

LEAKY_TXT = b"""Prepared by: Jane Doe
Contact: Raj Patel <raj.patel@acme-demo.test>
Escalations to mary.jones@acme-demo.test, or outsider@elsewhere.test
db_password = "Summer2024!xQ"
aws = AKIAIOSFODNN7EXAMPLE
url = postgres://svc_app:Hunter2Hunter2@db.acme-demo.test:5432/app
password: must be eight characters
password = changeme_here_
api_key = YOUR_API_KEY
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA
Thanks,
Priya Nair
"""


def doc_store(store, *urls):
    for u in urls:
        store.add_finding("documents", u, "documents_search", "search", u)


def test_doc_content_finds_addresses_names_and_masked_secrets(store):
    u = "https://www.acme-demo.test/old/notes.txt"
    doc_store(store, u)
    out = run("doc_content", store, FakeHttp(files={u: LEAKY_TXT}))
    vals = {(f.category, f.value) for f in out}
    assert ("emails", "raj.patel@acme-demo.test") in vals and ("emails", "mary.jones@acme-demo.test") in vals
    assert not any("elsewhere.test" in f.value for f in out)
    assert {"Jane Doe", "Raj Patel", "Priya Nair"} <= {f.value for f in out if f.category == "employees"}
    creds = [f.value for f in out if "line" in f.value]
    assert any(v.startswith("AWS access key AK") and "notes.txt line 5" in v for v in creds)
    assert any(v.startswith("Private key block in") for v in creds)
    assert any(v.startswith("Password in a URL") for v in creds)
    assert any(v.startswith("Password or secret") and "line 4" in v for v in creds)
    # prose and placeholders are not findings
    assert not any("line 7" in v or "line 9" in v for v in creds)


def test_doc_content_never_keeps_a_whole_secret(store):
    u = "https://www.acme-demo.test/old/notes.txt"
    doc_store(store, u)
    out = run("doc_content", store, FakeHttp(files={u: LEAKY_TXT}))
    blob = " ".join(f"{f.value} {f.notes} {f.url}" for f in out)
    for secret in ("Summer2024!xQ", "AKIAIOSFODNN7EXAMPLE", "Hunter2Hunter2", "MIIEowIBAAKCAQEA"):
        assert secret not in blob


def test_doc_content_reads_office_and_pdf_and_skips_the_rest(store):
    docx = io.BytesIO()
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("word/document.xml",
                   '<w:document xmlns:w="w"><w:body><w:p><w:t>Owner: Sam Rivera</w:t></w:p>'
                   '<w:p><w:t>mail sam.rivera@acme-demo.test</w:t></w:p></w:body></w:document>')
    urls = ["https://www.acme-demo.test/a.docx", "https://www.acme-demo.test/b.txt",
            "https://www.acme-demo.test/sitemap.xml", "https://www.acme-demo.test/c.png", "https://other.test/d.txt"]
    doc_store(store, *urls)
    http = FakeHttp(files={urls[0]: docx.getvalue(), urls[1]: b"\x00\x01\x02" * 400})
    out = run("doc_content", store, http)
    assert {f.value for f in out} == {"sam.rivera@acme-demo.test", "Sam Rivera"}
    assert http.downloads == urls[:2]       # the sitemap, the image and the off domain file are never fetched


def test_doc_content_survives_zip_bombs_and_broken_files(store):
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", b"<a>" + b"A" * (40 * 1024 * 1024) + b"</a>")
    urls = ["https://www.acme-demo.test/bomb.docx", "https://www.acme-demo.test/broken.pdf",
            "https://www.acme-demo.test/ok.txt"]
    doc_store(store, *urls)
    out = run("doc_content", store, FakeHttp(files={urls[0]: bomb.getvalue(), urls[1]: b"%PDF-1.4 nope",
                                                    urls[2]: b"Contact: Kim Lee\n"}))
    assert [f.value for f in out] == ["Kim Lee"]


def test_a_subdomain_inherits_the_parent_dmarc_record_instead_of_being_called_unprotected(monkeypatch):
    """Found in a real report: the apex had p=none, yet the intranet and remote runs reported 'DMARC record missing'."""
    stub_dns(monkeypatch, {("_dmarc.acme-demo.test", "TXT"): (['"v=DMARC1; p=none;"'], "ok")})
    store = Store.create("Deep", company="Acme Demo Corp", domain="intranet.acme-demo.test")
    out = {f.value: f for f in run("dns_records", store)}
    assert "DMARC record missing" not in out
    dmarc = next(f for v, f in out.items() if v.startswith("DMARC:"))
    assert dmarc.notes.startswith("Inherited from acme-demo.test.") and "monitor only" in dmarc.notes


def test_an_inherited_record_is_judged_by_sp_when_it_has_one(monkeypatch):
    stub_dns(monkeypatch, {("_dmarc.acme-demo.test", "TXT"): (['"v=DMARC1; p=none; sp=reject"'], "ok")})
    sub = {f.value: f for f in run("dns_records", Store.create("A", company="Acme", domain="portal.acme-demo.test"))}
    assert "monitor only" not in next(f for v, f in sub.items() if v.startswith("DMARC:")).notes     # subdomains follow sp=reject
    apex = {f.value: f for f in run("dns_records", Store.create("B", company="Acme", domain="acme-demo.test"))}
    assert "p=none, monitor only" in next(f for v, f in apex.items() if v.startswith("DMARC:")).notes  # the apex follows p=none


def test_sp_none_is_not_mistaken_for_p_none(monkeypatch):
    stub_dns(monkeypatch, {("_dmarc.acme-demo.test", "TXT"): (['"v=DMARC1; sp=none; p=reject"'], "ok")})
    out = {f.value: f for f in run("dns_records", Store.create("A", company="Acme", domain="acme-demo.test"))}
    assert "monitor only" not in next(f for v, f in out.items() if v.startswith("DMARC:")).notes


def test_dmarc_missing_everywhere_names_the_host(monkeypatch):
    stub_dns(monkeypatch, {})
    out = {f.value: f for f in run("dns_records", Store.create("A", company="Acme", domain="intranet.acme-demo.test"))}
    assert "intranet.acme-demo.test" in out["DMARC record missing"].notes


def test_the_parent_search_stops_before_the_top_level_domain(monkeypatch):
    asked = []
    monkeypatch.setattr(dp, "dns_lookup", lambda name, rtype: (asked.append(name) or ([], "empty")))
    assert dp.dmarc_lookup("a.b.acme-demo.test") == ([], None)
    assert asked == ["_dmarc.a.b.acme-demo.test", "_dmarc.b.acme-demo.test", "_dmarc.acme-demo.test"]   # never _dmarc.test
