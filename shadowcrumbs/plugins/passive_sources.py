"""Passive third party sources. Deep tier because they call an outside API, but none of them touches the client.

They do tell the outside service which domain you are asking about, so each description says so.
"""
import os

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
