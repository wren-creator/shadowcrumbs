"""Search layer. Search tier hits a search engine and caches every query per engagement.

Providers:
  ddg      DuckDuckGo HTML endpoint, no key, the default
  brave    Brave Search API, used on deep dives when BRAVE_API_KEY is set
  fixture  canned results from a JSON file, for demos and tests
"""
import json
import os
import random
import re
import threading
import time
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlparse

import requests
from bs4 import BeautifulSoup

from . import config

CACHE_TTL = 7 * 24 * 3600


@dataclass
class Result:
    title: str
    url: str
    snippet: str


class SearchBlocked(Exception):
    """The search engine is rate limiting or challenging us."""


class DuckDuckGoHTML:
    name = "ddg"

    def search(self, query, n):
        r = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers={"User-Agent": config.user_agent()},
            timeout=config.http_timeout(),
        )
        if r.status_code in (202, 403, 429) or "anomaly-modal" in r.text:
            raise SearchBlocked(
                "DuckDuckGo is throttling this IP. Wait a few minutes, raise SHADOWCRUMBS_SEARCH_DELAY, "
                "or set BRAVE_API_KEY and run a deep dive."
            )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        for div in soup.select("div.result"):
            a = div.select_one("a.result__a")
            if not a or not a.get("href"):
                continue
            if "result--ad" in (div.get("class") or []):
                continue
            url = self._unwrap(a["href"])
            if self._is_ad(url):
                continue
            snip = div.select_one(".result__snippet")
            out.append(Result(a.get_text(" ", strip=True), url, snip.get_text(" ", strip=True) if snip else ""))
            if len(out) >= n:
                break
        return out

    @staticmethod
    def _is_ad(url):
        """Sponsored links come back wrapped in duckduckgo.com/y.js, never a real result."""
        u = urlparse(url)
        return (u.hostname or "").endswith("duckduckgo.com") and u.path.startswith("/y.js")

    @staticmethod
    def _unwrap(href):
        if href.startswith("//"):
            href = "https:" + href
        qs = parse_qs(urlparse(href).query)
        return qs["uddg"][0] if "uddg" in qs else href


class Brave:
    name = "brave"

    def search(self, query, n):
        key = os.environ.get("BRAVE_API_KEY")
        if not key:
            raise RuntimeError("BRAVE_API_KEY is not set")
        r = requests.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": min(n, 20)},
            headers={"X-Subscription-Token": key, "Accept": "application/json"},
            timeout=config.http_timeout(),
        )
        if r.status_code == 429:
            raise SearchBlocked("Brave Search API rate limit hit")
        r.raise_for_status()
        rows = r.json().get("web", {}).get("results", [])
        return [
            Result(x.get("title", ""), x.get("url", ""), re.sub(r"<[^>]+>", "", x.get("description", "")))
            for x in rows
        ]


class FixtureProvider:
    """Reads {"entries": [{"match": "substring", "results": [{title, url, snippet}]}]}."""

    name = "fixture"

    def __init__(self, path):
        with open(path, encoding="utf-8") as f:
            self.entries = json.load(f)["entries"]

    def search(self, query, n):
        out = []
        for e in self.entries:
            if e["match"] in query:
                out.extend(Result(**r) for r in e["results"])
        return out[:n]


def make_provider(tier):
    name = config.search_provider(tier)
    if name == "ddg":
        return DuckDuckGoHTML()
    if name == "brave":
        return Brave()
    if name == "fixture":
        path = os.environ.get("SHADOWCRUMBS_FIXTURE")
        if not path:
            raise RuntimeError("SHADOWCRUMBS_FIXTURE must point at a fixture file")
        return FixtureProvider(path)
    raise ValueError(f"unknown search provider {name!r}")


class SearchClient:
    def __init__(self, provider, store=None, delay=None, sleep=time.sleep):
        self.provider = provider
        self.store = store
        self.delay = config.search_delay() if delay is None else delay
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last = 0.0
        self.live_queries = 0
        self.cached_queries = 0

    def search(self, query, n=20):
        if self.store:
            cached = self.store.cache_get(query, CACHE_TTL)
            if cached is not None:
                self.cached_queries += 1
                return [Result(**r) for r in cached]
        with self._lock:
            wait = self.delay * random.uniform(0.7, 1.3) - (time.monotonic() - self._last)
            if wait > 0:
                self._sleep(wait)
            results = self.provider.search(query, n)
            self._last = time.monotonic()
        self.live_queries += 1
        if self.store:
            self.store.cache_put(query, [asdict(r) for r in results])
        return results
