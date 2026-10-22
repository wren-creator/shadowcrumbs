"""TEMPLATE for a deep dive data source. This file is never loaded (names starting with _ are skipped).

Make a real one from it with:  python tools/new_plugin.py my_source --tier deep --category infrastructure --key-env MY_API_KEY
That copies this file to plugins_user/my_source.py with your name and category filled in.
Then edit the three marked spots and restart.

Deep dive sources run only after the engagement has an authorization reference. Two things to decide:
  * Does it send traffic to the client's own systems? Then set touches_target = True and the dashboard
    shows the ACTIVE badge. Asking a third party's API about the client does not count, but it does send
    the client's domain to that third party, so say so in the description.
  * Does it need an API key? Keys come from environment variables, never from a file in this repo.
    Never print or log one. The logs scrub the common shapes, but do not rely on that.
"""
import os

from shadowcrumbs.plugin import Finding, Plugin, register
from shadowcrumbs.util import clip

URL = ""             # 1. THE ENDPOINT. Left empty on purpose: until you fill it in, the source shows as skipped.
KEY_ENV = ""         # the environment variable holding the API key, or empty if it needs none


@register
class __CLASS__(Plugin):
    name = "__NAME__"
    tier = "deep"
    description = "__DESCRIPTION__"
    categories = ("__CATEGORY__",)       # employees, emails, documents, tech, subdomains, infrastructure
    needs_any = ("__NEEDS__",)           # runs when at least one of these target fields is set
    order = 50                           # lower runs first
    touches_target = __TOUCHES__         # True when traffic goes straight to the client

    def unavailable(self):
        """A short reason the source cannot run right now. The run is recorded as skipped with this text."""
        if not URL:
            return "still the template, set URL in this file"
        if KEY_ENV and not os.environ.get(KEY_ENV):
            return f"needs {KEY_ENV}"
        return None

    def verify(self, http):
        """Optional, but worth having. The Verify page and tools/verify_sources.py call this to check that your
        endpoint answers and your key is accepted, before anyone starts a scan. Make one cheap request, ask about
        example.com (never the client), and return (status, detail): ok, warn or fail. Do not put the key in the detail."""
        headers = {"Accept": "application/json"}
        if KEY_ENV:
            headers["X-Api-Key"] = os.environ[KEY_ENV]
        r = http.get(URL, params={"q": "example.com"}, headers=headers, timeout=10)
        if r.status_code in (401, 403):
            return "fail", f"the service rejected the key ({r.status_code}). Check {KEY_ENV or 'the key'}."
        if r.status_code == 429:
            return "warn", "rate limited (429). The key may be fine, try again in a minute."
        r.raise_for_status()
        return "ok", "endpoint answered" + (", key accepted" if KEY_ENV else "")

    def run(self, ctx):
        d = ctx.target.get("domain")

        # 2. THE REQUEST. ctx.http paces itself and logs method, URL, status and time (never headers).
        #    Put the key in a header, not the URL, so it cannot end up in a log line or an error message.
        headers = {"Accept": "application/json"}
        if KEY_ENV:
            headers["X-Api-Key"] = os.environ[KEY_ENV]          # check the vendor's docs for the real header name
        r = ctx.http.get(URL, params={"q": d}, headers=headers)
        if r.status_code in (401, 403):
            raise RuntimeError(f"{KEY_ENV or 'the service'} was refused ({r.status_code}). Check the key.")
        if r.status_code == 429:
            raise RuntimeError("rate limited, try again later")
        r.raise_for_status()

        # 3. WHAT TO RECORD. Turn each row of the response into a Finding.
        #    Never record a password or secret. Record that it exists, where, and what kind.
        for row in r.json().get("results", []):
            yield Finding("__CATEGORY__", clip(str(row.get("name") or row), 200), url=row.get("url"),
                          confidence=50, notes="from __NAME__")
