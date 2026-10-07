"""Credential exposure sources. Deep tier, so they wait for the authorization reference like everything else.

Three ways in, one finding shape:
  hibp_breaches      Have I Been Pwned, per address already found (HIBP_API_KEY)
  dehashed_domain    DeHashed, one search for the whole domain (DEHASHED_API_KEY)
  breach_file_import a CSV, JSONL or email:secret file from your own feed (SHADOWCRUMBS_BREACH_FILE)

Policy: no part of a password is ever stored. A finding says the address was exposed, where, and what
kind of secret leaked (plaintext or which sort of hash) and how long. Enough to write the report and
plan a spray, nothing you would mind losing from a laptop.

Note the first two send addresses you found to a third party. That is the point of them, and it is
why they are off until you set a key.
"""
import csv
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

from .. import config
from ..plugin import Finding, Plugin, register
from ..util import EMAIL_RE, clip

CACHE_TTL = 7 * 24 * 3600
HIBP_PACE = 6.5          # seconds between HIBP calls, the entry-level key allows about 10 a minute
HIBP_MAX_ADDRESSES = 100
FILE_MAX_FINDINGS = 500

HASH_SHAPES = [
    (re.compile(r"^\$2[abxy]?\$\d\d\$.{53}$"), "bcrypt hash"),
    (re.compile(r"^\$argon2"), "argon2 hash"),
    (re.compile(r"^\$6\$"), "SHA-512 crypt hash"),
    (re.compile(r"^\$5\$"), "SHA-256 crypt hash"),
    (re.compile(r"^\$1\$"), "MD5 crypt hash"),
    (re.compile(r"^[a-f0-9]{128}$", re.I), "SHA-512 looking hash"),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "SHA-256 looking hash"),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "SHA-1 looking hash"),
    (re.compile(r"^[a-f0-9]{32}$", re.I), "MD5 or NTLM looking hash"),
]


def classify_secret(secret):
    """Describe a leaked secret without keeping any of it. Returns text, or None when there is no secret."""
    secret = (secret or "").strip()
    if not secret:
        return None
    for rx, label in HASH_SHAPES:
        if rx.match(secret):
            return label
    return f"plaintext password, {len(secret)} characters"


def in_scope(address, domain):
    host = address.rsplit("@", 1)[-1].lower()
    return host == domain or host.endswith("." + domain)


def credential_finding(email, source, what, plugin_note, confidence):
    return Finding("emails", f"Exposed credential: {email} in {source}", confidence=confidence,
                   notes=clip(f"{what}. {plugin_note}", 900))


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


@register
class HibpBreaches(Plugin):
    name = "hibp_breaches"
    tier = "deep"
    description = "Which known breaches each harvested address shows up in (Have I Been Pwned). Sends the addresses to HIBP."
    categories = ("emails",)
    needs_any = ("domain",)
    order = 40

    def unavailable(self):
        return None if os.environ.get("HIBP_API_KEY") else "needs HIBP_API_KEY"

    def run(self, ctx):
        d = ctx.target["domain"]
        key = os.environ["HIBP_API_KEY"]
        addresses = sorted({
            f["value"].lower() for f in ctx.store.findings("emails")
            if EMAIL_RE.fullmatch(f["value"]) and in_scope(f["value"], d)
        })[:HIBP_MAX_ADDRESSES]
        for addr in addresses:
            for breach in self._lookup(ctx, key, addr):
                classes = breach.get("DataClasses") or []
                what = ("Passwords were in this breach (HIBP does not say plaintext or hashed)"
                        if "Passwords" in classes else "No passwords listed for this breach")
                yield credential_finding(
                    addr, breach.get("Name", "unknown breach"), what,
                    f"Breached {breach.get('BreachDate', 'date unknown')}. Also exposed: "
                    + ", ".join(c for c in classes if c != "Passwords")[:300],
                    confidence=80,
                )

    def _lookup(self, ctx, key, addr):
        cache_key = f"hibp:{addr}"
        cached = ctx.store.cache_get(cache_key, CACHE_TTL)
        if cached is not None:
            return cached
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(addr)}?truncateResponse=false"
        for attempt in range(2):
            time.sleep(HIBP_PACE)
            r = ctx.http.get(url, headers={"hibp-api-key": key, "user-agent": "Shadowcrumbs"})
            if r.status_code == 404:
                breaches = []
                break
            if r.status_code == 401:
                raise RuntimeError("HIBP rejected the key (401). Check HIBP_API_KEY.")
            if r.status_code == 429 and attempt == 0:
                time.sleep(min(int(r.headers.get("Retry-After", "10")), 60))
                continue
            if r.status_code == 429:
                raise RuntimeError("HIBP rate limit hit twice, stopping. Try again in a few minutes.")
            r.raise_for_status()
            breaches = r.json()
            break
        ctx.store.cache_put(cache_key, breaches)
        return breaches


@register
class DehashedDomain(Plugin):
    name = "dehashed_domain"
    tier = "deep"
    description = "Every address at the domain that appears in DeHashed's breach data, and what kind of secret leaked."
    categories = ("emails",)
    needs_any = ("domain",)
    order = 41

    PAGE = 500
    MAX_PAGES = 3

    def unavailable(self):
        return None if os.environ.get("DEHASHED_API_KEY") else "needs DEHASHED_API_KEY"

    def run(self, ctx):
        d = ctx.target["domain"]
        key = os.environ["DEHASHED_API_KEY"]
        for page in range(1, self.MAX_PAGES + 1):
            cache_key = f"dehashed:{d}:{page}"
            data = ctx.store.cache_get(cache_key, CACHE_TTL)
            if data is None:
                r = ctx.http.post(
                    "https://api.dehashed.com/v2/search",
                    headers={"Dehashed-Api-Key": key, "Content-Type": "application/json"},
                    json={"query": f"domain:{d}", "page": page, "size": self.PAGE},
                )
                if r.status_code in (401, 403):
                    raise RuntimeError(f"DeHashed rejected the key ({r.status_code}). Check DEHASHED_API_KEY and credits.")
                if r.status_code == 429:
                    raise RuntimeError("DeHashed rate limit hit, stopping. Try again in a few minutes.")
                r.raise_for_status()
                data = r.json()
                ctx.store.cache_put(cache_key, data)
            entries = data.get("entries") or []
            for e in entries:
                source = e.get("database_name") or "unknown database"
                secrets = _as_list(e.get("password")) + _as_list(e.get("hashed_password"))
                what = next(filter(None, (classify_secret(s) for s in secrets)), "No secret recorded, address only")
                for addr in _as_list(e.get("email")):
                    if EMAIL_RE.fullmatch(addr or "") and in_scope(addr, d):
                        yield credential_finding(addr.lower(), source, what, "Source: DeHashed.", confidence=85)
            if len(entries) < self.PAGE:
                break


@register
class BreachFileImport(Plugin):
    name = "breach_file_import"
    tier = "deep"
    description = "Reads your own breach feed (CSV, JSONL or email:secret lines) and keeps rows for this domain."
    categories = ("emails",)
    needs_any = ("domain",)
    order = 42

    def unavailable(self):
        path = os.environ.get("SHADOWCRUMBS_BREACH_FILE")
        if not path:
            return "needs SHADOWCRUMBS_BREACH_FILE"
        if not Path(path).is_file():
            return f"SHADOWCRUMBS_BREACH_FILE is not a file: {path}"
        return None

    def run(self, ctx):
        d = ctx.target["domain"]
        path = Path(os.environ["SHADOWCRUMBS_BREACH_FILE"])
        count = 0
        for email, secret, source in self._rows(path):
            if not EMAIL_RE.fullmatch(email) or not in_scope(email, d):
                continue
            what = classify_secret(secret) or "No secret recorded, address only"
            yield credential_finding(email.lower(), source, what, f"Source: {path.name}.", confidence=75)
            count += 1
            if count >= FILE_MAX_FINDINGS:
                break

    @staticmethod
    def _rows(path):
        """Yield (email, secret, source) without holding the file in memory."""
        default_source = path.stem
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            if path.suffix.lower() == ".csv":
                for row in csv.DictReader(f):
                    low = {(k or "").lower(): v for k, v in row.items()}
                    yield (low.get("email") or low.get("username") or "").strip(), \
                        low.get("password") or low.get("hash") or low.get("hashed_password") or "", \
                        low.get("source") or low.get("breach") or low.get("database") or default_source
            elif path.suffix.lower() in (".jsonl", ".ndjson"):
                for line in f:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict):
                        low = {str(k).lower(): v for k, v in row.items()}
                        yield str(low.get("email") or "").strip(), \
                            str(low.get("password") or low.get("hash") or low.get("hashed_password") or ""), \
                            str(low.get("source") or low.get("breach") or low.get("database") or default_source)
            else:
                for line in f:
                    email, _, secret = line.strip().partition(":")
                    yield email.strip(), secret, default_source
