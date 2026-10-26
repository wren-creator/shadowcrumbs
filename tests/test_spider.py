import pytest

from shadowcrumbs.plugin import REGISTRY, Context, load_plugins
from shadowcrumbs.plugins import spider
from shadowcrumbs.store import Store

load_plugins()

HOME = b"""<html><head><title>Intranet</title><meta name="generator" content="Hugo 0.120"></head><body>
<p>Please <a href="upload_image.html">upload your profile image</a></p>
<ul><li><a href="passwords.xlsx">passwords.xlsx</a></li><li><a href="problem-code.txt">problem-code.txt</a></li>
<li><a href="remote-access-guide.docx">guide</a></li><li><a href="links.html">links</a></li>
<li><a href="style.css">css</a></li><li><a href="https://evil.example/x.pdf">elsewhere</a></li></ul>
<a href="mailto:${contact.email}">contact</a></body></html>"""
LINKS = b"""<html><body><ul>
<li><a href="http://contacts.acme.test">contacts</a></li>
<li><a href="http://mainframe.acme.test:23">mainframe.acme.test (port:23) GUEST login</a></li>
<li><a href="/admin/">admin</a></li></ul>
<p>Contact <a href="mailto:Webmaster@acme.test">webmaster@acme.test</a> or other@elsewhere.com</p></body></html>"""
UPLOAD = b"""<form action="/up" method="post"><input type="file" name="f"></form>
<form action="/login"><input type="password" name="p"></form>"""


class Resp:
    def __init__(self, status=200, body=b"", ctype="text/html", location=None):
        self.status_code, self.body = status, body
        self.headers = {"Content-Type": ctype, **({"Location": location} if location else {})}

    def iter_content(self, n):
        yield self.body

    def close(self):
        pass


class Http:
    def __init__(self, pages, live=("intranet.acme.test",)):
        self.pages, self.live, self.fetched = pages, live, []

    def probe(self, host):
        return {"scheme": "https", "status": 200} if host in self.live else None

    def get(self, url, **kw):
        assert kw["allow_redirects"] is False, "redirects must be followed by hand so they stay in scope"
        self.fetched.append(url)
        return self.pages.get(url, Resp(404))


@pytest.fixture
def store():
    s = Store.create("Spider", company="Acme", domain="acme.test")
    s.add_finding("subdomains", "intranet.acme.test", "t", "search")
    return s


def run(store, http):
    meta = store.meta()
    ctx = Context(target={k: meta[k] for k in ("company", "domain", "ip")}, search=None, http=http, store=store)
    return list(REGISTRY["site_spider"].run(ctx))


def pages():
    return {"https://intranet.acme.test/": Resp(body=HOME), "https://intranet.acme.test/links.html": Resp(body=LINKS),
            "https://intranet.acme.test/upload_image.html": Resp(body=UPLOAD)}


def test_extract_reads_links_emails_forms_and_generator():
    out = spider.extract(LINKS, "https://intranet.acme.test/links.html", "acme.test")
    assert ("http://mainframe.acme.test:23", "mainframe.acme.test (port:23) GUEST login") in out["links"]
    assert out["emails"] == {"webmaster@acme.test"}               # the outside address is dropped
    assert spider.extract(UPLOAD, "https://a.acme.test/", "acme.test")["forms"] == {"login", "upload"}
    assert spider.extract(HOME, "https://a.acme.test/", "acme.test")["generator"] == "Hugo 0.120"
    assert spider.extract(HOME, "https://a.acme.test/", "acme.test")["emails"] == set()   # the ${contact.email} template is not an address


def test_it_follows_links_and_reports_what_the_pages_give_away(store):
    http = Http(pages())
    found = {(f.category, f.value): f for f in run(store, http)}
    doc = found[("documents", "https://intranet.acme.test/passwords.xlsx")]
    assert doc.confidence == 85 and "credentials" in doc.notes and "Linked from intranet.acme.test/" in doc.notes
    assert found[("documents", "https://intranet.acme.test/problem-code.txt")].confidence == 75
    assert ("emails", "webmaster@acme.test") in found
    assert ("subdomains", "contacts.acme.test") in found
    port = found[("infrastructure", "mainframe.acme.test:23 is linked from the site")]
    assert "GUEST login" in port.notes
    assert ("exposures", "https://intranet.acme.test/admin/") in found
    assert ("exposures", "https://intranet.acme.test/upload_image.html (file upload form)") in found
    assert ("exposures", "https://intranet.acme.test/upload_image.html (login form)") in found
    assert ("tech", "Generator: Hugo 0.120") in found


def test_it_never_fetches_documents_assets_or_other_domains(store):
    http = Http(pages())
    run(store, http)
    assert not any(u.endswith((".xlsx", ".txt", ".docx", ".css")) for u in http.fetched)
    assert not any("evil.example" in u or "elsewhere.com" in u for u in http.fetched)


def test_a_redirect_that_leaves_the_domain_is_not_followed(store):
    http = Http({"https://intranet.acme.test/": Resp(302, location="https://evil.example/landing")})
    assert run(store, http) == []
    assert http.fetched == ["https://intranet.acme.test/"]


def test_the_page_limit_stops_a_crawl(store, monkeypatch):
    monkeypatch.setattr("shadowcrumbs.config.MAX_SPIDER_PAGES", 1)
    http = Http(pages())
    run(store, http)
    assert len(http.fetched) == 1


def test_a_new_host_found_on_a_page_is_crawled_too(store):
    p = pages()
    p["https://contacts.acme.test/"] = Resp(body=b'<a href="mailto:hr@acme.test">hr</a>')
    found = {(f.category, f.value) for f in run(store, Http(p, live=("intranet.acme.test", "contacts.acme.test")))}
    assert ("emails", "hr@acme.test") in found
