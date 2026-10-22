"""HTTP client for deep dive plugins. Everything that talks to a target or an API goes through here."""
import time

import requests
import urllib3
from bs4 import BeautifulSoup

from . import config
from .log import safe_url

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    def __init__(self, delay=0.4):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.user_agent()
        self._last = 0.0
        self.log = lambda msg, level="info": None   # the engine swaps in the run's event log

    def _logged(self, method, url, send):
        """Run one request and note method, URL, status and time. Never headers or bodies, they carry keys."""
        began = time.monotonic()
        try:
            r = send()
        except Exception as e:
            self.log(f"{method} {safe_url(url)} failed after {time.monotonic() - began:.1f}s: {type(e).__name__}: {e}", "error")
            raise
        code = getattr(r, "status_code", "?")
        self.log(f"{method} {safe_url(url)} -> {code} in {time.monotonic() - began:.1f}s", "warning" if isinstance(code, int) and code >= 400 else "debug")
        return r

    def _pace(self):
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url, timeout=None, **kw):
        self._pace()
        return self._logged("GET", url, lambda: self.session.get(url, timeout=timeout or config.http_timeout(), **kw))

    def post(self, url, timeout=None, **kw):
        self._pace()
        return self._logged("POST", url, lambda: self.session.post(url, timeout=timeout or config.http_timeout(), **kw))

    def head(self, url, timeout=None, **kw):
        self._pace()
        return self._logged("HEAD", url, lambda: self.session.head(url, timeout=timeout or config.http_timeout(), allow_redirects=True, **kw))

    def get_json(self, url, timeout=None):
        """JSON body, or None on a 404. Other HTTP errors raise."""
        r = self.get(url, timeout=timeout, headers={"Accept": "application/json"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def download(self, url, max_bytes=None):
        """Fetch a file with a hard size cap. Returns bytes, or None when it is too big."""
        cap = max_bytes or config.MAX_DOWNLOAD_BYTES
        self._pace()
        with self._logged("GET", url, lambda: self.session.get(url, stream=True, timeout=config.http_timeout())) as r:
            r.raise_for_status()
            declared = int(r.headers.get("Content-Length") or 0)
            if declared > cap:
                return None
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf.extend(chunk)
                if len(buf) > cap:
                    return None
            return bytes(buf)

    def probe(self, host):
        """GET the root of a host over https then http. Returns a dict, or None if nothing answers."""
        for scheme in ("https", "http"):
            try:
                self._pace()
                r = self._logged("GET", f"{scheme}://{host}/", lambda: self.session.get(
                    f"{scheme}://{host}/", timeout=config.http_timeout(), verify=False,
                    allow_redirects=True, stream=True,
                ))
            except requests.RequestException:
                continue
            try:
                body = r.raw.read(65536, decode_content=True) or b""
            finally:
                r.close()
            title = None
            try:
                t = BeautifulSoup(body, "html.parser").title
                title = t.get_text(" ", strip=True)[:150] if t else None
            except Exception:
                pass
            return {
                "scheme": scheme,
                "status": r.status_code,
                "final_url": r.url,
                "server": r.headers.get("Server"),
                "powered_by": r.headers.get("X-Powered-By"),
                "aspnet": r.headers.get("X-AspNet-Version"),
                "title": title,
            }
        return None
