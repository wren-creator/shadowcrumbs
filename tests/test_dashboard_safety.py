"""The dashboard shows text scraped from the open web. None of it may ever run, become markup, or become a bad link.

Two layers:
  1. A source check that always runs: the dashboard code contains no way to turn a string into HTML or code.
  2. A real browser test: the real app, hostile findings, and a look at what actually landed in the page.
     It needs Chromium. It skips, saying why, when none is found. See CONTRIBUTING.md.
"""
import glob
import os
import re
import socket
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = [
    r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\s*\(", r"new\s+Function\b",
    r"\.srcdoc", r"createContextualFragment", r"setAttribute\(\s*[\"']on", r"dangerouslySetInnerHTML",
    r"setTimeout\(\s*[\"']", r"setInterval\(\s*[\"']",
]


@pytest.mark.parametrize("path", ["static/app.js", "static/index.html"])
def test_dashboard_source_has_no_way_to_make_markup_or_code_from_strings(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", text) if path.endswith(".js") else text      # a comment may name the rule
    for pattern in FORBIDDEN:
        assert not re.search(pattern, code), f"{path} uses {pattern}. Render scraped text with textContent only."
    if path.endswith(".html"):
        assert not re.search(r"\bon[a-z]+\s*=", code, re.I), "inline event handlers in index.html"
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", code), "inline script in index.html"


def test_only_http_and_https_urls_pass_the_link_filter():
    js = (ROOT / "static/app.js").read_text(encoding="utf-8")
    body = re.search(r"function safeUrl\(u\) \{(.*?)\n\}", js, re.S).group(1)
    assert 'protocol === "http:"' in body and 'protocol === "https:"' in body
    assert "javascript" not in body and "data:" not in body                         # an allowlist, not a blocklist


# --- real browser ------------------------------------------------------------------------

PAYLOAD_IMG = "<img src=x onerror=window.__pwned=1>"
PAYLOAD_SCRIPT = "<script>window.__pwned=1</script>"
PAYLOAD_BREAKOUT = '"><svg onload=window.__pwned=1>'
BAD_URLS = [
    "javascript:window.__pwned=1", "JaVaScRiPt:window.__pwned=1", "  javascript:window.__pwned=1",
    "data:text/html,<script>window.__pwned=1</script>", "vbscript:msgbox(1)", "file:///etc/passwd", "//evil.test/x",
]
GOOD_URL = "https://ok.example/evidence"


def find_chromium():
    candidates = [os.environ.get("SHADOWCRUMBS_TEST_BROWSER")]
    for base in ("~/Library/Caches/ms-playwright", "~/.cache/ms-playwright"):
        candidates += sorted(glob.glob(os.path.expanduser(base) + "/chromium*/*/chrome-headless-shell"))
        candidates += sorted(glob.glob(os.path.expanduser(base) + "/chromium*/*/*/chrome-headless-shell"))
    return next((c for c in candidates if c and Path(c).is_file()), None)


@pytest.fixture
def page():
    sync_api = pytest.importorskip("playwright.sync_api", reason="pip install playwright (see requirements-dev.txt)")
    with sync_api.sync_playwright() as p:
        browser = None
        try:
            browser = p.chromium.launch()
        except Exception:
            exe = find_chromium()
            if exe:
                browser = p.chromium.launch(executable_path=exe)
        if browser is None:
            pytest.skip("no Chromium found. Run `playwright install chromium` or set SHADOWCRUMBS_TEST_BROWSER to a chrome binary")
        pg = browser.new_page()
        yield pg
        browser.close()


@pytest.fixture
def live_app():
    import uvicorn
    from shadowcrumbs.app import app
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    end = time.time() + 10
    while not server.started and time.time() < end:
        time.sleep(0.05)
    assert server.started, "test server did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=5)


def plant_hostile_data():
    from shadowcrumbs.store import Store
    s = Store.create(PAYLOAD_IMG, company=PAYLOAD_SCRIPT, domain="acme-demo.test", auth_ref=PAYLOAD_BREAKOUT, authorized=True)
    for cat in ("employees", "emails", "documents", "tech", "subdomains", "infrastructure"):
        s.add_finding(cat, f"{PAYLOAD_IMG} {cat}", PAYLOAD_SCRIPT, "search", GOOD_URL, 50, f"{PAYLOAD_BREAKOUT} <b>bold</b>")
        for i, bad in enumerate(BAD_URLS):
            s.add_finding(cat, f"bad url {i} {PAYLOAD_SCRIPT}", PAYLOAD_IMG, "search", bad, 50, PAYLOAD_SCRIPT)
    rid = s.start_run(PAYLOAD_IMG, "search")
    s.finish_run(rid, "error", 0, f"{PAYLOAD_SCRIPT} {PAYLOAD_BREAKOUT}")
    return s


def test_hostile_findings_stay_inert_text_in_the_real_dashboard(page, live_app):
    store = plant_hostile_data()
    errors, dialogs = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))

    page.goto(live_app, wait_until="networkidle")
    page.wait_for_selector("#findings .cats button")
    for cat_button in page.locator("#findings .cats button").all():
        cat_button.click()
        page.wait_for_selector("#findings table")
        assert page.evaluate("window.__pwned") is None
    page.locator("#runs summary").click()

    # nothing ran
    assert page.evaluate("window.__pwned") is None and dialogs == [] and errors == []

    # nothing became markup
    assert page.evaluate("""() => document.querySelectorAll(
        '#main img, #main script, #main iframe, #main object, #main embed, #main svg, #main style, #main b, #tabs img, #tabs script'
    ).length""") == 0
    assert page.evaluate("""() => [...document.querySelectorAll('#main *, #tabs *')]
        .some(e => [...e.attributes].some(a => a.name.startsWith('on')))""") is False

    # the hostile strings are visible, literally
    assert PAYLOAD_IMG in page.locator("#tabs").inner_text()
    assert PAYLOAD_IMG in page.locator("#head").inner_text()
    assert PAYLOAD_SCRIPT in page.locator("#head").inner_text()
    assert page.locator("#auth-ref").input_value() == PAYLOAD_BREAKOUT
    assert PAYLOAD_SCRIPT in page.locator("#runs").inner_text()
    assert "<b>bold</b>" in page.locator("#findings").inner_text()

    # every link on the page is http or https, and the good one is there with a safe rel
    hrefs = page.evaluate("() => [...document.querySelectorAll('#main a[href]')].map(a => a.href)")
    assert hrefs and all(h.startswith(("http://", "https://")) for h in hrefs), hrefs
    assert GOOD_URL in page.evaluate("() => [...document.querySelectorAll('#findings a')].map(a => a.href)")
    assert page.locator(f"#findings a[href='{GOOD_URL}']").first.get_attribute("rel") == "noopener noreferrer"
    assert page.evaluate("""() => [...document.querySelectorAll('#main a[target=_blank]')].every(a => a.rel.includes('noopener'))""")
    store.delete_files()
