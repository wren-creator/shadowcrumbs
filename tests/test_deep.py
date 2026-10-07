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
