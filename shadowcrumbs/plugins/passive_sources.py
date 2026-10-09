"""Passive third party sources. Deep tier because they call an outside API, but none of them touches the client.

They do tell the outside service which domain you are asking about, so each description says so.
"""
import os
import re
import time

from ..plugin import Finding, Plugin, register
from ..signatures import scan
from ..util import clip, in_domain

URLSCAN_TTL = 24 * 3600


@register
class UrlscanSearch(Plugin):
    name = "urlscan_search"
    tier = "deep"
    description = (
        "Hosts, IPs and server software seen in public urlscan.io scans of the domain. "
        "Sends the domain to urlscan.io. No key needed, the free search reaches back 30 days."
    )
    categories = ("subdomains", "infrastructure", "tech")
    needs_any = ("domain",)
    order = 36

    def run(self, ctx):
        d = ctx.target["domain"]
        rows = self._search(ctx, d)
        hosts, nets, servers = {}, {}, {}
        for row in rows:
            page = row.get("page") or {}
            host = (page.get("domain") or "").lower()
            if not in_domain(host, d):          # the search can return scans that merely mention the domain
                continue
            evidence = f"https://urlscan.io/result/{row.get('_id') or (row.get('task') or {}).get('uuid')}/"
            when = (row.get("task") or {}).get("time", "")[:10]
            hosts.setdefault(host, (evidence, when))
            if page.get("ip"):
                net = page.get("asnname") or page.get("asn") or "unknown network"
                entry = nets.setdefault((host, net), {"ips": set(), "evidence": evidence, "when": when})
                entry["ips"].add(page["ip"])
                if when > entry["when"]:         # point the evidence link at the newest scan
                    entry["evidence"], entry["when"] = evidence, when
            if page.get("server"):
                servers.setdefault((host, page["server"]), (evidence, when, page.get("title") or ""))

        for host, (evidence, when) in sorted(hosts.items()):
            if host != d:
                yield Finding("subdomains", host, url=evidence, confidence=80,
                              notes=f"Seen in a public urlscan.io scan on {when}.")
        for (host, net), e in sorted(nets.items()):
            ips = sorted(e["ips"])
            shown = ", ".join(ips[:4]) + (f" and {len(ips) - 4} more" if len(ips) > 4 else "")
            yield Finding("infrastructure", f"{host} on {clip(net, 60)}: {shown}", url=e["evidence"], confidence=70,
                          notes=f"{len(ips)} address{'es' if len(ips) != 1 else ''} across urlscan.io scans, newest {e['when']}. "
                                "History, so it may have changed since.")
        for (host, server), (evidence, when, title) in sorted(servers.items()):
            yield Finding("tech", f"Server: {server}", url=evidence, confidence=60,
                          notes=f"Seen on {host} in a urlscan.io scan on {when}.")
            for name, _ in scan(f"{title} {server}"):
                yield Finding("tech", name, url=evidence, confidence=45,
                              notes=f"Page title or server header on {host}: {clip(title + ' ' + server, 100)}")

    def _search(self, ctx, d):
        cache_key = f"urlscan:{d}"
        cached = ctx.store.cache_get(cache_key, URLSCAN_TTL)
        if cached is not None:
            return cached
        headers = {"User-Agent": "Shadowcrumbs", "Accept": "application/json"}
        key = os.environ.get("URLSCAN_API_KEY")
        if key:                                  # optional, raises the limits and the 30 day window
            headers["API-Key"] = key
        # plain page.domain also matches subdomains. Wildcards and regexes are refused for anonymous users.
        r = ctx.http.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"page.domain:{d}", "size": 100}, headers=headers)
        if r.status_code == 429:
            wait = r.headers.get("X-Rate-Limit-Reset-After", "a minute")
            raise RuntimeError(f"urlscan.io rate limit hit, stopping. Try again in about {wait} seconds.")
        if r.status_code in (401, 403):
            raise RuntimeError(f"urlscan.io rejected the request ({r.status_code}). Check URLSCAN_API_KEY.")
        if r.status_code == 400:
            raise RuntimeError("urlscan.io rejected the search query. Is the target domain valid?")
        r.raise_for_status()
        rows = r.json().get("results") or []
        ctx.store.cache_put(cache_key, rows)
        return rows


GITHUB_TTL = 24 * 3600
GITHUB_PAGE_PAUSE = 6.5     # code search allows about 10 requests a minute
GITHUB_PAGES = 2
GITHUB_MAX_REPOS = 50
VENDORED = re.compile(r"(^|/)(site-packages|node_modules|\.?venv|[a-z]*venv|vendor|third_party|\.git)/", re.I)
CONFIG_LIKE = re.compile(
    r"(\.env|config|credential|secret|settings|\.pem$|\.key$|id_rsa|\.npmrc|\.pgpass|\.tfvars|docker-compose|"
    r"\.ya?ml$|\.ini$|\.properties$|\.conf$)", re.I)


@register
class GithubCodeSearch(Plugin):
    name = "github_code_search"
    tier = "deep"
    description = (
        "Public GitHub code that mentions the domain: repos, hostnames and addresses found in it, and config-like files "
        "worth a look. Sends the domain to GitHub. Needs a free GITHUB_TOKEN. Keeps only repo, path, hostnames and "
        "addresses, never the code itself."
    )
    categories = ("infrastructure", "subdomains", "emails")
    needs_any = ("domain",)
    order = 37

    def unavailable(self):
        return None if os.environ.get("GITHUB_TOKEN") else "needs GITHUB_TOKEN"

    def run(self, ctx):
        d = ctx.target["domain"]
        repos = {}
        hosts, emails = {}, {}
        for hit in self._search(ctx, d):
            if VENDORED.search(hit["path"]):        # copies of other people's libraries say nothing about the client
                continue
            repo = repos.setdefault(hit["repo"], {"paths": [], "url": hit["url"], "config": False})
            repo["paths"].append(hit["path"])
            repo["config"] = repo["config"] or bool(CONFIG_LIKE.search(hit["path"]))
            for h in hit["hosts"]:
                hosts.setdefault(h, hit["repo"])
            for e in hit["emails"]:
                emails.setdefault(e, hit["repo"])
        for name, r in sorted(repos.items())[:GITHUB_MAX_REPOS]:
            sample = ", ".join(r["paths"][:3]) + (f" and {len(r['paths']) - 3} more" if len(r["paths"]) > 3 else "")
            n = len(r["paths"])
            note = f"{n} file{'s' if n != 1 else ''} mention{'' if n != 1 else 's'} the domain: {sample}."
            if r["config"]:
                note += " Includes config-like files, worth a look by hand."
            yield Finding("infrastructure", f"Public code mentions {d}: {name}", url=r["url"],
                          confidence=55 if r["config"] else 40, notes=clip(note, 900))
        for h, repo in sorted(hosts.items()):
            if h != d:
                yield Finding("subdomains", h, url=f"https://github.com/{repo}", confidence=55,
                              notes=f"Named in public code in {repo}.")
        for e, repo in sorted(emails.items()):
            yield Finding("emails", e, url=f"https://github.com/{repo}", confidence=55,
                          notes=f"Named in public code in {repo}.")

    def _search(self, ctx, d):
        """Hits reduced to repo, path, link, hostnames and addresses. The code fragments are dropped before
        anything is cached, because public repos leak secrets and none of that belongs in an engagement database."""
        cache_key = f"github_code:{d}"
        cached = ctx.store.cache_get(cache_key, GITHUB_TTL)
        if cached is not None:
            return cached
        host_re = re.compile(r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9-]+\.)*" + re.escape(d) + r")(?![A-Za-z0-9-])", re.I)
        mail_re = re.compile(r"[A-Za-z0-9._%+-]+@" + re.escape(d) + r"(?![A-Za-z0-9-])", re.I)
        hits = []
        for page in range(1, GITHUB_PAGES + 1):
            if page > 1:
                time.sleep(GITHUB_PAGE_PAUSE)
            r = ctx.http.get(
                "https://api.github.com/search/code",
                params={"q": f'"{d}"', "per_page": 100, "page": page},
                headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "User-Agent": "Shadowcrumbs",
                         "Accept": "application/vnd.github.text-match+json", "X-GitHub-Api-Version": "2022-11-28"},
            )
            if r.status_code == 401:
                raise RuntimeError("GitHub rejected the token (401). Check GITHUB_TOKEN.")
            if r.status_code in (403, 429):
                wait = r.headers.get("Retry-After") or r.headers.get("X-RateLimit-Reset") or "a minute"
                raise RuntimeError(f"GitHub refused the search (rate limit or no access, {r.status_code}). Wait and retry ({wait}).")
            if r.status_code == 422:
                raise RuntimeError("GitHub rejected the search query. Is the target domain valid?")
            r.raise_for_status()
            body = r.json()
            for item in body.get("items") or []:
                repo = item.get("repository") or {}
                # A token with private repo access can see private code in search. Only public code is a finding.
                if repo.get("fork") or not repo.get("full_name") or repo.get("private") or repo.get("visibility") not in (None, "public"):
                    continue
                text = " ".join(m.get("fragment", "") for m in item.get("text_matches") or [])
                hits.append({
                    "repo": repo["full_name"], "path": item.get("path", ""), "url": item.get("html_url", ""),
                    "hosts": sorted({h.lower() for h in host_re.findall(text) if in_domain(h.lower(), d)}),
                    "emails": sorted({e.lower() for e in mail_re.findall(text)}),
                })
            if len(body.get("items") or []) < 100:
                break
        ctx.store.cache_put(cache_key, hits)
        return hits
