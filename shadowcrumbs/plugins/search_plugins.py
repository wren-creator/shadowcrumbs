"""Search tier. These only read what search engines already show, nothing touches the client."""
import re
from urllib.parse import urlparse

from ..content import SKIPPED_NAMES
from ..plugin import Finding, Plugin, register
from ..signatures import scan
from ..util import EMAIL_RE, clip, email_format, guess_company, hostname, in_domain, placeholder_email, window

DOC_EXTS = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf", "odt", "ods",
            "md", "xml", "json", "log", "yml", "yaml", "ini", "conf", "cfg", "env", "sql", "bak", "properties")


def doc_ext(url):
    path = urlparse(url).path.lower()
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
    if path.rsplit("/", 1)[-1].startswith(SKIPPED_NAMES):     # sitemap.xml and friends are public by design
        return None
    return ext if ext in DOC_EXTS else None


def company_of(target):
    return target.get("company") or guess_company(target.get("domain"))


@register
class SubdomainsSearch(Plugin):
    name = "subdomains_search"
    tier = "search"
    description = "Finds subdomains with site: queries, then excludes what it found to dig for more."
    categories = ("subdomains",)
    needs_any = ("domain",)
    order = 10

    def run(self, ctx):
        d = ctx.target["domain"]
        seen = set()

        def harvest(q):
            for r in ctx.search.search(q):
                h = hostname(r.url)
                if h and h != d and in_domain(h, d) and h not in seen:
                    seen.add(h)
                    yield Finding("subdomains", h, url=r.url, confidence=70, notes=clip(r.title, 120))

        for q in (f"site:{d}", f"site:{d} -www", f"site:{d} login OR portal OR vpn OR remote OR webmail"):
            yield from harvest(q)
        if seen:
            excluded = " ".join(f"-site:{h}" for h in sorted(seen)[:10])
            yield from harvest(f"site:{d} {excluded}")


@register
class DocumentsSearch(Plugin):
    name = "documents_search"
    tier = "search"
    description = "Finds exposed PDFs, Office files, text and config files, and white papers on the domain and under the company name."
    categories = ("documents",)
    needs_any = ("domain", "company")
    order = 20

    def run(self, ctx):
        d, company = ctx.target.get("domain"), ctx.target.get("company")
        queries = []
        if d:
            queries += [f"site:{d} filetype:{e}" for e in ("pdf", "docx", "xlsx", "pptx", "doc", "xls")]
            queries += [f"site:{d} filetype:txt", f"site:{d} filetype:xml",
                        f"site:{d} filetype:log OR filetype:conf OR filetype:ini OR filetype:yml OR filetype:sql"]
        if company:
            queries += [
                f'"{company}" whitepaper OR "white paper" OR "case study" filetype:pdf',
                f'"{company}" architecture OR implementation filetype:pdf',
            ]
        seen = set()
        for q in queries:
            for r in ctx.search.search(q):
                ext = doc_ext(r.url)
                if not ext or r.url in seen:
                    continue
                on_domain = bool(d) and in_domain(hostname(r.url) or "", d)
                if not on_domain:
                    blob = f"{r.title} {r.snippet}".lower()
                    if not (company and company.lower() in blob):
                        continue
                seen.add(r.url)
                note = f"{ext.upper()}: {clip(r.title, 120)}"
                if not on_domain:
                    note += " (off domain, check it is really theirs)"
                yield Finding("documents", r.url, url=r.url, confidence=80 if on_domain else 45, notes=note)


@register
class EmailsSearch(Plugin):
    name = "emails_search"
    tier = "search"
    description = "Harvests addresses at the domain from search results and guesses the address format."
    categories = ("emails",)
    needs_any = ("domain",)
    order = 30

    def run(self, ctx):
        d = ctx.target["domain"]
        found = {}
        for q in (f'"@{d}"', f'"@{d}" email', f'site:{d} "@{d}"', f'"@{d}" filetype:pdf'):
            for r in ctx.search.search(q):
                text = f"{r.title} {r.snippet}"
                for m in EMAIL_RE.findall(text):
                    e = m.lower().strip(".")
                    host = e.split("@", 1)[1]
                    if placeholder_email(e, in_domain(hostname(r.url) or "", d)):
                        continue
                    if (host == d or host.endswith("." + d)) and e not in found:
                        found[e] = r
                        user = e.split("@", 1)[0]
                        yield Finding("emails", e, url=r.url, confidence=70,
                                      notes=f"Login ID candidate: {user}. " + clip(r.snippet, 120))
        fmt = email_format(list(found), d)
        if fmt:
            label, hits, total = fmt
            yield Finding("emails", f"format: {label}@{d}", confidence=40,
                          notes=f"{hits} of {total} harvested addresses match this pattern")


LINKEDIN_TITLE = re.compile(
    r"^(?P<name>[^|\-–—,]{3,60}?)(?:,[^\-–—|]*)?\s+[-–—]\s+(?P<rest>.+?)\s*\|\s*LinkedIn\s*$", re.I
)


@register
class ExposureSearch(Plugin):
    name = "exposure_search"
    tier = "search"
    description = ("Sensitive looking documents, architecture files, public cloud storage and paste or code site mentions. "
                   "Only operators every search engine handles (site:, filetype:, quotes, OR). Reads listings, never the pages.")
    categories = ("documents", "emails", "infrastructure")
    needs_any = ("domain", "company")
    order = 25

    def run(self, ctx):
        d, company = ctx.target.get("domain"), company_of(ctx.target)
        plan = []     # (kind, query, label)
        if d:
            plan += [
                ("doc", f'site:{d} filetype:pdf "internal use only" OR confidential OR "do not distribute"', "marked sensitive"),
                ("doc", f"site:{d} filetype:pdf architecture OR \"network diagram\" OR runbook", "architecture or runbook"),
                ("doc", f"site:{d} filetype:xlsx directory OR roster OR \"contact list\"", "people list"),
                ("mention", f'site:pastebin.com OR site:github.com "@{d}"', ""),
                ("format", f'"{company}" "email format" OR "firstname.lastname@{d}"', ""),
            ]
        plan.append(("cloud", f'site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com "{company}"', ""))
        seen = set()
        for kind, q, label in plan:
            for r in ctx.search.search(q):
                if kind == "doc":
                    ext = doc_ext(r.url)
                    if ext and r.url not in seen and in_domain(hostname(r.url) or "", d):
                        seen.add(r.url)
                        yield Finding("documents", r.url, url=r.url, confidence=75,
                                      notes=f"{ext.upper()}, {label}: {clip(r.title, 120)}")
                elif kind in ("mention", "format"):
                    # only the address and where it showed up. The listing text is not kept: a paste can hold anything.
                    text = f"{r.title} {r.snippet}" if kind == "format" else f"{r.title} {r.snippet} {r.url}"
                    for m in EMAIL_RE.findall(text):
                        e = m.lower().strip(".")
                        if placeholder_email(e, in_domain(hostname(r.url) or "", d)):
                            continue
                        if e.split("@", 1)[1].endswith(d) and ("email", e) not in seen:
                            seen.add(("email", e))
                            where = hostname(r.url) or "a public page"
                            yield Finding("emails", e, url=r.url, confidence=55, notes=f"Seen on {where}")
                elif kind == "cloud":
                    host = hostname(r.url) or ""
                    # the bucket itself has to carry the name. A textbook page that mentions the client does not count.
                    key = re.sub(r"[^a-z0-9]", "", company.lower())
                    stem = d.split(".")[0] if d else ""
                    where = re.sub(r"[^a-z0-9]", "", r.url.lower())
                    if not ((key and key in where) or (len(stem) >= 4 and stem in where)):
                        continue
                    first = urlparse(r.url).path.strip("/").split("/", 1)[0]
                    value = f"cloud storage: {host}/{first}".rstrip("/")
                    if value not in seen:
                        seen.add(value)
                        yield Finding("infrastructure", value, url=r.url, confidence=40,
                                      notes="Public cloud storage that mentions the client: " + clip(r.title, 100))


@register
class EmployeesSearch(Plugin):
    name = "employees_search"
    tier = "search"
    description = "Names and job titles from LinkedIn result titles. Reads the search listing, never LinkedIn itself."
    categories = ("employees",)
    needs_any = ("company", "domain")
    order = 40

    def run(self, ctx):
        company = company_of(ctx.target)
        seen = set()
        queries = [
            f'site:linkedin.com/in "{company}"',
            f'site:linkedin.com/in "{company}" administrator OR engineer OR analyst',
            f'site:linkedin.com/in "{company}" mainframe OR "AS/400" OR "IBM i" OR SCADA OR PLC',
            f'site:linkedin.com/in "{company}" security OR CISO OR "IT director"',
            f'site:linkedin.com/in "{company}" "help desk" OR "service desk" OR sysadmin',
        ]
        for q in queries:
            for r in ctx.search.search(q):
                if "linkedin.com/in/" not in r.url:
                    continue
                if company.lower() not in f"{r.title} {r.snippet}".lower():
                    continue
                m = LINKEDIN_TITLE.match(r.title.strip())
                if not m:
                    continue
                name = m.group("name").strip()
                if any(ch.isdigit() for ch in name) or name.lower() in seen:
                    continue
                seen.add(name.lower())
                role = m.group("rest").strip()
                yield Finding("employees", name, url=r.url, confidence=65, notes=clip(role, 140))


@register
class TechSearch(Plugin):
    name = "tech_search"
    tier = "search"
    description = "Spots tech stack hints in job posts and public posts, with the sentence it came from."
    categories = ("tech",)
    needs_any = ("company", "domain")
    order = 50

    def run(self, ctx):
        company, d = company_of(ctx.target), ctx.target.get("domain")
        queries = [
            f'"{company}" jobs "experience with" administrator OR engineer',
            f'"{company}" "IBM i" OR "AS/400" OR iSeries',
            f'"{company}" "z/OS" OR "z/TPF" OR mainframe',
            f'"{company}" SCADA OR PLC OR "Allen-Bradley" OR Siemens',
            # people brag: profile blurbs and posts name the products they run
            f'site:linkedin.com/in "{company}" responsible OR managed OR implemented OR "experience with"',
            f'site:linkedin.com/posts "{company}" upgraded OR migrated OR "go live" OR deployed',
            # job ads list the exact products they run
            f'site:indeed.com OR site:greenhouse.io OR site:lever.co "{company}" Linux OR AWS OR Azure OR Splunk',
        ]
        if d:
            queries += [f"site:{d} careers OR jobs", f'site:{d} "powered by" OR version OR "release notes"']
        seen = set()
        for q in queries:
            for r in ctx.search.search(q):
                blob = f"{r.title} {r.snippet}"
                about_them = company.lower() in blob.lower() or (d and d in f"{blob} {r.url}".lower())
                if not about_them:
                    continue
                for name, m in scan(blob):
                    if name in seen:
                        continue
                    seen.add(name)
                    yield Finding("tech", name, url=r.url, confidence=45,
                                  notes=f'"{window(blob, m.start(), m.end())}"')
