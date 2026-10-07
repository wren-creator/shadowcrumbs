"""Example user plugin. Drop a file like this in plugins_user/ and it shows up in the dashboard.

This one asks the Internet Archive which URLs it has ever seen on the domain and keeps the
ones that smell interesting: admin panels, backups, configs, old logins.
"""
import re

from shadowcrumbs.plugin import Finding, Plugin, register
from shadowcrumbs.util import clip

INTERESTING = re.compile(
    r"(admin|login|logon|signin|portal|backup|\.bak|\.old|\.sql|\.zip|\.env|\.git|config|phpinfo|"
    r"wp-admin|jenkins|grafana|kibana|swagger|/api/|test|staging|dev)",
    re.I,
)


@register
class WaybackUrls(Plugin):
    name = "wayback_urls"
    tier = "deep"
    description = "Historical URLs from the Internet Archive that look like admin pages, backups or configs."
    categories = ("infrastructure",)
    needs_any = ("domain",)
    order = 35

    def run(self, ctx):
        d = ctx.target["domain"]
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{d}&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        rows = ctx.http.get_json(url, timeout=60) or []
        hits = 0
        for row in rows[1:]:  # first row is the header
            original = row[0]
            if INTERESTING.search(original):
                hits += 1
                yield Finding("infrastructure", f"Archived URL: {clip(original, 200)}", url=original,
                              confidence=35, notes="Seen by the Internet Archive. May no longer exist.")
                if hits >= 150:
                    break
