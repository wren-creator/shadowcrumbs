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
