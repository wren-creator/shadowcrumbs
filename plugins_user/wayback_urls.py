"""Example user plugin. Drop a file like this in plugins_user/ and it shows up in the dashboard.

This one asks the Internet Archive which URLs it has ever seen on the domain and keeps the
ones that smell interesting: admin panels, backups, configs, old logins.
"""
import re
import time
from urllib.parse import urlparse

import requests

from shadowcrumbs.plugin import Finding, Plugin, register
from shadowcrumbs.util import clip

INTERESTING = re.compile(
    r"(admin|login|logon|signin|portal|backup|\.bak|\.old|\.sql|\.zip|\.env|\.git|config|phpinfo|"
    r"wp-admin|jenkins|grafana|kibana|swagger|/api/|test|staging|dev)",
    re.I,
)


RETRY_STATUS = {429, 502, 503, 504}   # the Archive says "busy", so wait and ask again
PAUSES = (0, 5, 15)                   # seconds before each of the three tries
TRY_TIMEOUT = 45                      # their server needs 10 to 50 seconds even for a domain with almost nothing archived


@register
class WaybackUrls(Plugin):
    name = "wayback_urls"
    tier = "deep"
    description = "Historical URLs from the Internet Archive that look like admin pages, backups or configs."
    categories = ("infrastructure",)
    needs_any = ("domain",)
    order = 35

    def verify(self, http):
        try:
            rows = http.get_json("https://web.archive.org/cdx/search/cdx?url=example.com&output=json&limit=1", timeout=30)
        except (requests.Timeout, requests.ConnectionError):
            return "warn", "the Internet Archive did not answer in 30 seconds. It is often slow, a scan waits and retries."
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in RETRY_STATUS:
                return "warn", f"the Internet Archive is busy right now (HTTP {e.response.status_code}), a scan waits and retries"
            raise
        return ("ok", "the Internet Archive answered") if rows else ("warn", "the Internet Archive answered with nothing")

    def _cdx(self, ctx, url):
        """Ask the Archive's index, patiently. Timeouts and "busy" answers get two more tries after a pause.
        A 403 means we are being rate limited, and asking again makes that worse, so it stops there."""
        last = "no answer"
        for wait in PAUSES:
            if wait:
                ctx.log(f"wayback_urls: the Internet Archive was busy ({last}), trying again in {wait}s", "warning")
                time.sleep(wait)
            try:
                r = ctx.http.get(url, timeout=TRY_TIMEOUT, headers={"Accept": "application/json"})
            except (requests.Timeout, requests.ConnectionError) as e:
                last = type(e).__name__
                continue
            if r.status_code == 404:
                return []
            if r.status_code == 403:
                raise RuntimeError("the Internet Archive refused the request (403), which usually means it was asked too often. "
                                   "Wait a few minutes and run this source again")
            if r.status_code in RETRY_STATUS:
                last = f"HTTP {r.status_code}"
                continue
            r.raise_for_status()
            try:
                rows = r.json()
            except ValueError:            # an error page that came back as a 200
                last = "unreadable reply"
                continue
            return rows if isinstance(rows, list) else []
        raise RuntimeError(f"the Internet Archive did not answer after {len(PAUSES)} tries ({last}). "
                           "It is often slow or overloaded, so run this source again later")

    def run(self, ctx):
        d = ctx.target["domain"]
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{d}&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        rows = self._cdx(ctx, url) or []
        hits = 0
        for row in rows[1:]:  # first row is the header
            original = row[0]
            u = urlparse(original)
            if INTERESTING.search(f"{u.path}?{u.query}"):      # the path, never the host: "dev" must not match devcorp.com
                hits += 1
                yield Finding("infrastructure", f"Archived URL: {clip(original, 200)}", url=original,
                              confidence=35, notes="Seen by the Internet Archive. May no longer exist.")
                if hits >= 150:
                    break
