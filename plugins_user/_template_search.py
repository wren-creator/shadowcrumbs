"""TEMPLATE for a search tier data source. This file is never loaded (names starting with _ are skipped).

Make a real one from it with:  python tools/new_plugin.py my_source --tier search --category tech
That copies this file to plugins_user/my_source.py with your name, category and queries filled in.
Then edit the three marked spots and restart. It shows up in the dashboard on its own.

The search tier only reads what search engines already show. Nothing here touches the client.
"""
from shadowcrumbs.plugin import Finding, Plugin, register
from shadowcrumbs.util import clip, hostname, in_domain


@register
class __CLASS__(Plugin):
    name = "__NAME__"
    tier = "search"
    description = "__DESCRIPTION__"
    categories = ("__CATEGORY__",)       # employees, emails, documents, tech, subdomains, infrastructure
    needs_any = ("__NEEDS__",)           # runs when at least one of these target fields is set
    order = 50                           # lower runs first

    def run(self, ctx):
        d = ctx.target.get("domain")
        company = ctx.target.get("company")

        # 1. THE DATA POINTS. One search per line. {d} is the domain, {company} the company name.
        #    Search operators work: site:, filetype:, intitle:, "exact phrase", OR, -exclude.
        queries = [
            # __QUERIES__
        ]

        # A query that mentions a field this target does not have (no company given, say) would search for
        # the word None, so drop those.
        queries = [q for q in queries if "None" not in q]

        seen = set()
        for q in queries:
            for r in ctx.search.search(q):          # cached per engagement, paced, and logged for you
                # 2. KEEP ONLY WHAT IS REALLY THEIRS. Search engines return neighbours and noise.
                if d and not in_domain(hostname(r.url) or "", d):
                    continue
                if r.url in seen:
                    continue
                seen.add(r.url)

                # 3. WHAT TO RECORD. r.title, r.url and r.snippet are all you get from a search result.
                #    Pull the interesting part out of them here, a regex over r.snippet is typical.
                #    confidence: how direct the evidence is, 0 to 100. notes: why you think so.
                yield Finding("__CATEGORY__", clip(r.title or r.url, 200), url=r.url, confidence=50,
                              notes=clip(r.snippet, 200))
