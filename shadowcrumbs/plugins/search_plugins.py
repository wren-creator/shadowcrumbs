"""Search tier. These only read what search engines already show, nothing touches the client."""
import re
from urllib.parse import urlparse

from ..plugin import Finding, Plugin, register
from ..signatures import scan
from ..util import EMAIL_RE, clip, email_format, guess_company, hostname, in_domain, window

DOC_EXTS = ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf", "odt", "ods")


def doc_ext(url):
    path = urlparse(url).path.lower()
    ext = path.rsplit(".", 1)[-1] if "." in path else ""
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
    description = "Finds exposed PDFs, Office files and white papers on the domain and under the company name."
    categories = ("documents",)
    needs_any = ("domain", "company")
    order = 20

    def run(self, ctx):
        d, company = ctx.target.get("domain"), ctx.target.get("company")
        queries = []
        if d:
            queries += [f"site:{d} filetype:{e}" for e in ("pdf", "docx", "xlsx", "pptx", "doc", "xls")]
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
