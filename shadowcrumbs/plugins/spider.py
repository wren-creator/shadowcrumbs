"""Follows links on the client's own sites, the way a person clicking around an intranet would.

A front page rarely says much. The pages behind it do: a links page naming other hosts, a resources list with a
spreadsheet called passwords, a contact address, an upload form. Everything stays inside the target domain.
"""
import re
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .. import config
from ..paths import classify, notes_for
from ..plugin import Finding, Plugin, register
from ..util import EMAIL_RE, clip, hostname, in_domain, placeholder_email
from .search_plugins import DOC_EXTS

MAX_BYTES = 256 * 1024
MAX_HOPS = 4                                    # redirects followed by hand, each one checked against the scope
ASSET_RE = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|mp[34]|avi|mov|zip|gz|tgz|exe|iso)$", re.I)
DOC_RE = re.compile(r"\.(" + "|".join(DOC_EXTS) + r")$", re.I)
# a file name that gives away what is inside, worth saying out loud in the note
TELLING_RE = re.compile(r"pass(word|wd)?s?|cred|secret|token|private|backup|dump|confidential|remote[-_ ]?access|vpn|\bkeys?\b", re.I)
DEFAULT_PORTS = {None, 80, 443}


def extract(body, page_url, domain):
    """Pull what matters out of one page: links with their text, in-domain emails, forms, the generator tag."""
    soup = BeautifulSoup(body, "html.parser")
    links, emails = [], set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith("mailto:"):
            addr = href[7:].split("?", 1)[0].strip().lower()
            if EMAIL_RE.fullmatch(addr):
                emails.add(addr)
            continue
        url = urldefrag(urljoin(page_url, href))[0]
        if urlparse(url).scheme in ("http", "https"):
            links.append((url, a.get_text(" ", strip=True)))
    for tag in soup.find_all(["form", "iframe", "frame"]):
        src = tag.get("action") if tag.name == "form" else tag.get("src")
        if src:
            url = urldefrag(urljoin(page_url, src.strip()))[0]
            if urlparse(url).scheme in ("http", "https"):
                links.append((url, ""))
    for m in EMAIL_RE.findall(soup.get_text(" ")):
        emails.add(m.lower().strip("."))
    emails = {e for e in emails if e.split("@", 1)[1] == domain or e.split("@", 1)[1].endswith("." + domain)}
    emails = {e for e in emails if not placeholder_email(e, True)}
    forms = set()
    for f in soup.find_all("form"):
        if f.find("input", attrs={"type": re.compile("^password$", re.I)}):
            forms.add("login")
        if f.find("input", attrs={"type": re.compile("^file$", re.I)}):
            forms.add("upload")
    gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    return {"links": links, "emails": emails, "forms": forms, "generator": (gen.get("content") or "").strip() if gen else ""}


@register
class SiteSpider(Plugin):
    name = "site_spider"
    tier = "deep"
    description = (
        "Follows links on the domain and every live subdomain, two clicks deep, and reports what the pages give away: "
        "linked documents (which are then opened and read), other hosts, ports named in links, contact addresses, "
        "login and upload forms. Never leaves the client's domain. One GET per page, with a page limit."
    )
    categories = ("documents", "subdomains", "emails", "exposures", "infrastructure", "tech")
    needs_any = ("domain",)
    order = 55
    touches_target = True

    def _fetch(self, ctx, url, domain):
        """(final_url, html bytes) for an HTML page, else None. Redirects are followed one at a time and only
        while they stay inside the domain, so a page can never send the crawler somewhere else."""
        for _ in range(MAX_HOPS):
            if not in_domain(hostname(url) or "", domain):
                return None
            r = None
            try:
                r = ctx.http.get(url, timeout=10, allow_redirects=False, stream=True, verify=False)
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    url = urljoin(url, r.headers["Location"])
                    continue
                if r.status_code != 200 or "html" not in (r.headers.get("Content-Type") or "").lower():
                    return None
                body = b""
                for chunk in r.iter_content(32768):
                    body += chunk
                    if len(body) >= MAX_BYTES:
                        break
                return url, body
            except requests.RequestException:
                return None
            finally:
                if r is not None and hasattr(r, "close"):
                    r.close()
        return None

    def run(self, ctx):
        d = ctx.target["domain"]
        known = {f["value"] for f in ctx.store.findings("subdomains")}
        todo = deque([d] + sorted(known))
        queued, reported, pages, hosts_done = set(todo), set(), 0, 0
        while todo and pages < config.MAX_SPIDER_PAGES and hosts_done < config.MAX_PROBE_HOSTS:
            host = todo.popleft()
            info = ctx.http.probe(host)
            if not info:
                continue
            hosts_done += 1
            frontier, seen, host_pages = deque([(f"{info['scheme']}://{host}/", 0)]), set(), 0
            while frontier and host_pages < config.MAX_SPIDER_PAGES_PER_HOST and pages < config.MAX_SPIDER_PAGES:
                url, depth = frontier.popleft()
                if url in seen:
                    continue
                seen.add(url)
                got = self._fetch(ctx, url, d)
                if not got:
                    continue
                page, body = got
                pages += 1
                host_pages += 1
                where = urlparse(page).path or "/"
                data = extract(body, page, d)
                for addr in sorted(data["emails"]):
                    if ("e", addr) not in reported:
                        reported.add(("e", addr))
                        yield Finding("emails", addr, url=page, confidence=80, notes=f"Published on {hostname(page)}{where}.")
                if data["generator"] and ("g", data["generator"]) not in reported:
                    reported.add(("g", data["generator"]))
                    yield Finding("tech", f"Generator: {clip(data['generator'], 80)}", url=page, confidence=80,
                                  notes=f"Meta tag on {hostname(page)}{where}.")
                for kind in sorted(data["forms"]):
                    yield Finding("exposures", f"{page} ({'login' if kind == 'login' else 'file upload'} form)", url=page, confidence=80,
                                  notes=notes_for(kind, f"Form on {hostname(page)}{where}. Confirm by hand."))
                for link, text in data["links"]:
                    u = urlparse(link)
                    lhost = (u.hostname or "").lower()
                    if not in_domain(lhost, d):
                        continue
                    if lhost != d and lhost not in known and ("h", lhost) not in reported:
                        reported.add(("h", lhost))
                        yield Finding("subdomains", lhost, url=page, confidence=80, notes=f"Linked from {hostname(page)}{where}.")
                    if lhost not in queued:
                        queued.add(lhost)
                        todo.append(lhost)
                    if u.port not in DEFAULT_PORTS and ("p", lhost, u.port) not in reported:
                        reported.add(("p", lhost, u.port))
                        yield Finding("infrastructure", f"{lhost}:{u.port} is linked from the site", url=page, confidence=80,
                                      notes=f"Link text: {clip(text, 100) or 'none'}. Seen on {hostname(page)}{where}.")
                        continue
                    path = u.path or "/"
                    if DOC_RE.search(path) and link not in reported:
                        reported.add(link)
                        telling = TELLING_RE.search(path.rsplit("/", 1)[-1])
                        yield Finding("documents", link, url=link, confidence=85 if telling else 75,
                                      notes=("The file name suggests credentials or access details. " if telling else "")
                                            + f"Linked from {hostname(page)}{where}. It is opened and read by the document sources.")
                    elif not ASSET_RE.search(path):
                        kind = classify(link)
                        if kind and kind[0] != "file" and link not in reported:
                            reported.add(link)
                            yield Finding("exposures", link, url=link, confidence=70,
                                          notes=notes_for(kind[0], f"Linked from {hostname(page)}{where}."))
                        if depth < config.MAX_SPIDER_DEPTH and lhost == (hostname(page) or "") and link not in seen:
                            frontier.append((link, depth + 1))
