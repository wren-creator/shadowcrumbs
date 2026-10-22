"""Deep dive: read the text of files found on the client's domain. Separate from doc_metadata on purpose, because
this one reads what is written inside the files, so it is its own button and its own line in the run history."""
from urllib.parse import unquote, urlparse

from .. import config
from ..content import extract_text, find_emails, find_names, find_secrets, readable
from ..plugin import Finding, Plugin, register
from ..util import hostname, in_domain


@register
class DocContent(Plugin):
    name = "doc_content"
    tier = "deep"
    description = ("Downloads text, config, PDF and Office files found on the client's domain and reads inside them for "
                   "email addresses, names in author and contact lines, and passwords or keys. Secrets are masked, never stored whole.")
    categories = ("emails", "employees")
    needs_any = ("domain",)
    order = 65
    touches_target = True

    def run(self, ctx):
        d = ctx.target["domain"]
        urls = [f["value"] for f in ctx.store.findings("documents") if in_domain(hostname(f["value"]), d) and readable(f["value"])]
        for url in urls[: config.MAX_DOCS_PER_RUN]:
            try:
                data = ctx.http.download(url)
                text = extract_text(url, data) if data else None
            except Exception as e:
                ctx.log(f"skipped {url}: {type(e).__name__}: {e}")
                continue
            if not text:
                ctx.log(f"nothing readable in {url}", "debug")
                continue
            base = unquote(urlparse(url).path.rsplit("/", 1)[-1])[:80] or url
            for addr in find_emails(text, d):
                yield Finding("emails", addr, url=url, confidence=65, notes=f"Written inside {base}.")
            for who in find_names(text):
                yield Finding("employees", who, url=url, confidence=50,
                              notes=f"Named in an author, contact or sign-off line inside {base}.")
            for label, masked, line, conf in find_secrets(text):
                shown = f"{label} {masked}".strip()
                yield Finding("emails", f"{shown} in {base} line {line}", url=url, confidence=conf,
                              notes="Masked on purpose, the full value is not stored. Open the file to see it, "
                                    "and report it to the client before it goes in a deliverable.")
