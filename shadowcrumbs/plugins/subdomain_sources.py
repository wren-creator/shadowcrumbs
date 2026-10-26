"""More ways to find subdomains, next to crt.sh: public passive DNS and certificate lists, and a wordlist guess.

Names found here land in the subdomains category, so resolve_subdomains and http_probe pick them up unchanged.
"""
import json
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import requests

from .. import config
from ..plugin import Finding, Plugin, register
from ..util import in_domain
from .deep_plugins import dns_check

HOST_RE = re.compile(r"[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_\-]*[a-z0-9_])?)*")


def clean(name, domain):
    """A real subdomain of domain, lowercased with any wildcard prefix gone, or None."""
    n = str(name or "").strip().lower().lstrip("*.").rstrip(".")
    return n if n and n != domain and in_domain(n, domain) and HOST_RE.fullmatch(n) else None


def _json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def parse_hackertarget(text, domain):
    """Lines of host,ip. Errors and quota messages come back as a 200 with no comma in them."""
    return {h for h in (clean(line.split(",", 1)[0], domain) for line in text.splitlines() if "," in line) if h}


def parse_otx(text, domain):
    data = _json(text)
    rows = data.get("passive_dns", []) if isinstance(data, dict) else []
    return {h for h in (clean(r.get("hostname"), domain) for r in rows if isinstance(r, dict)) if h}


def parse_certspotter(text, domain):
    data = _json(text)
    names = (n for e in (data if isinstance(data, list) else []) if isinstance(e, dict) for n in e.get("dns_names", []))
    return {h for h in (clean(n, domain) for n in names) if h}


def parse_jldc(text, domain):
    data = _json(text)
    return {h for h in (clean(n, domain) for n in (data if isinstance(data, list) else [])) if h}


SOURCES = (
    ("certspotter", "https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names", parse_certspotter),
    ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={d}", parse_hackertarget),
    ("otx", "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", parse_otx),
    ("jldc", "https://jldc.me/anubis/subdomains/{d}", parse_jldc),
)


@register
class PassiveSubdomains(Plugin):
    name = "passive_subdomains"
    tier = "deep"
    description = (
        "Subdomains from four keyless public sources: CertSpotter, HackerTarget, AlienVault OTX and JLDC. "
        "Sends the domain to each of them. Never touches the client. One source being down does not stop the rest."
    )
    categories = ("subdomains",)
    needs_any = ("domain",)
    order = 31

    def verify(self, http):
        return "unchecked", "four public services, none needs a key. Not probed here, HackerTarget's free daily quota is small."

    def run(self, ctx):
        d = ctx.target["domain"]
        found, failed = {}, []
        for name, url, parse in SOURCES:
            try:
                r = ctx.http.get(url.format(d=d), timeout=30, headers={"Accept": "application/json"})
                if r.status_code != 200:
                    failed.append(f"{name} (HTTP {r.status_code})")
                    continue
                hosts = parse(r.text, d)
            except requests.RequestException as e:
                failed.append(f"{name} ({type(e).__name__})")
                continue
            for h in hosts:
                found.setdefault(h, []).append(name)
        for f in failed:
            ctx.log(f"passive_subdomains: {f} gave nothing", "warning")
        if failed and not found and len(failed) == len(SOURCES):
            raise RuntimeError("none of the four passive sources answered: " + ", ".join(failed))
        for h, srcs in sorted(found.items()):
            yield Finding("subdomains", h, confidence=85 if len(srcs) > 1 else 75,
                          notes=f"Listed by {', '.join(srcs)}. Passive record, resolve_subdomains checks it is live.")


def a_records(name):
    """Set of A addresses for name, empty when it does not resolve."""
    try:
        res = dns.resolver.Resolver()
        res.lifetime = res.timeout = 3
        return {a.to_text() for a in res.resolve(name, "A")}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        return set()


def load_words(path=None):
    p = path or config.subdomain_wordlist()
    try:
        lines = p.read_text().splitlines()
    except OSError:
        return []
    words = [w.strip().lower() for w in lines if w.strip() and not w.lstrip().startswith("#")]
    return list(dict.fromkeys(w for w in words if re.fullmatch(r"[a-z0-9_\-]{1,63}", w)))


@register
class SubdomainBrute(Plugin):
    name = "subdomain_brute"
    tier = "deep"
    description = (
        "Guesses subdomain names from a wordlist (mainframe names included) and keeps the ones that resolve. "
        "Finds hosts that never appeared in a certificate, like autodiscover or intranet. "
        "Sends DNS lookups for each guess, so it is gated like the rest of the deep tier."
    )
    categories = ("subdomains",)
    needs_any = ("domain",)
    order = 32
    touches_target = True

    def verify(self, http):
        return dns_check()

    def run(self, ctx):
        d = ctx.target["domain"]
        # a wildcard zone answers for every name, so note what a made up name returns and ignore exactly that
        wild = set()
        for _ in range(2):
            wild |= a_records("".join(random.choices(string.ascii_lowercase + string.digits, k=16)) + "." + d)
        if wild:
            ctx.log(f"subdomain_brute: wildcard DNS on {d} ({', '.join(sorted(wild))}), ignoring names that only return that", "warning")
        known = {f["value"] for f in ctx.store.findings("subdomains")}
        words = [w for w in load_words()[: config.MAX_BRUTE_WORDS] if f"{w}.{d}" not in known]
        names = [f"{w}.{d}" for w in words]
        with ThreadPoolExecutor(max_workers=32) as pool:
            for name, ips in zip(names, pool.map(a_records, names)):
                real = ips - wild
                if real:
                    yield Finding("subdomains", name, confidence=90,
                                  notes=f"Guessed from the wordlist, resolves to {', '.join(sorted(real))}.")
