"""Markdown, JSON and PDF exports carry every supporting link and a confidence label, not just the first source."""
from shadowcrumbs import exporters
from shadowcrumbs.store import Store


def demo():
    s = Store.create("Acme", domain="acme.test")
    s.add_finding("subdomains", "vpn.acme.test", "subdomains_search", "search",
                  url="https://engine.example/r1", confidence=70)
    s.add_finding("subdomains", "vpn.acme.test", "crtsh", "deep",
                  url="https://crt.sh/?q=vpn.acme.test", confidence=85)
    return s


def test_markdown_lists_every_source_link_and_a_confidence_label():
    md = exporters.to_markdown(demo())
    assert "[subdomains_search](https://engine.example/r1)" in md
    assert "[crtsh](https://crt.sh/?q=vpn.acme.test)" in md
    assert "(high)" in md       # 70 and 85 compound well past the medium cutoff


def test_json_carries_the_raw_evidence_list_and_confidence_label():
    bundle = exporters._bundle(demo())
    (f,) = [f for f in bundle["findings"] if f["category"] == "subdomains"]
    links = {e["url"] for e in f["evidence"]}
    assert links == {"https://engine.example/r1", "https://crt.sh/?q=vpn.acme.test"}
    assert f["confidence_label"] == "high"


def test_pdf_builds_without_error_for_a_finding_with_several_evidence_links():
    assert exporters.to_pdf(demo()).startswith(b"%PDF")


def hostile():
    s = demo()
    s.add_finding("exposures", "https://acme.test/.well-known/ai-plugin.json", "wayback_urls", "deep",
                  url="https://acme.test/.well-known/ai-plugin.json", confidence=35)
    s.add_finding("exposures", "bad one", "x", "search", url='javascript:alert(1)')
    s.add_finding("exposures", "quote", "x", "search", url='https://acme.test/a"onmouseover="x')
    s.add_finding("exposures", "<script>alert(1)</script>", "x", "search", url="https://acme.test/p(1)")
    return s


def test_html_export_has_real_links_that_open_in_a_new_tab():
    page = exporters.to_html(demo())
    assert '<a href="https://crt.sh/?q=vpn.acme.test" target="_blank" rel="noopener noreferrer">' in page
    assert "<script" not in page and "http-equiv" not in page


def test_only_http_links_become_clickable_and_nothing_can_break_out_of_the_markup():
    s = hostile()
    page, md = exporters.to_html(s), exporters.to_markdown(s)
    assert 'href="javascript:' not in page and "](javascript:" not in md
    assert 'onmouseover="x' not in page.replace("&quot;", "")      # the quote is escaped, so it stays inside the attribute
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "(https://acme.test/p%281%29)" in md                      # a bracket in the URL no longer ends the markdown link


def test_pdf_evidence_is_clickable(monkeypatch):
    import reportlab.platypus.paragraph as para
    seen = []
    orig = para.Paragraph.__init__
    monkeypatch.setattr(para.Paragraph, "__init__", lambda self, text, *a, **k: (seen.append(text), orig(self, text, *a, **k))[1])
    assert exporters.to_pdf(hostile()).startswith(b"%PDF")
    assert any('<a href="https://acme.test/.well-known/ai-plugin.json"' in t for t in seen)
    assert not any('href="javascript:' in t for t in seen)
