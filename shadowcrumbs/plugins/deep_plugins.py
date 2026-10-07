"""Deep dive tier. Direct APIs and live lookups. Locked until the engagement has an authorization reference.

Plugins marked touches_target send traffic to the client's own systems.
"""
import io
import zipfile

import dns.exception
import dns.resolver
from defusedxml import ElementTree as ET

from .. import config
from ..plugin import Finding, Plugin, register
from ..signatures import scan
from ..util import clip, first_ip, hostname, in_domain


def dns_lookup(name, rtype):
    """Returns (records, status). status is ok, empty, nxdomain or error."""
    try:
        ans = dns.resolver.resolve(name, rtype, lifetime=6)
        return [a.to_text() for a in ans], "ok"
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "empty"
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return [], "error"


@register
class DnsRecords(Plugin):
    name = "dns_records"
    tier = "deep"
    description = "A, AAAA, MX, NS and TXT records, plus SPF and DMARC posture."
    categories = ("infrastructure",)
    needs_any = ("domain",)
    order = 10
    touches_target = True

    def run(self, ctx):
        d = ctx.target["domain"]
        for rtype in ("A", "AAAA", "MX", "NS"):
            records, _ = dns_lookup(d, rtype)
            for rec in records:
                yield Finding("infrastructure", f"{rtype} {rec.rstrip('.')}", confidence=95, notes=d)

        txt, _ = dns_lookup(d, "TXT")
        spf = [t.strip('"') for t in txt if "v=spf1" in t]
        if not spf:
            yield Finding("infrastructure", "SPF record missing", confidence=90,
                          notes="Nothing stops spoofed mail from claiming this domain.")
        for s in spf:
            note = "Hard fail, good."
            if "+all" in s:
                note = "Allows any sender. Mail spoofing is trivial."
            elif "~all" in s:
                note = "Soft fail only. Spoofed mail may still land."
            elif "?all" in s:
                note = "Neutral policy, effectively no protection."
            yield Finding("infrastructure", f"SPF: {clip(s, 200)}", confidence=90, notes=note)

        dmarc, _ = dns_lookup(f"_dmarc.{d}", "TXT")
        dmarc = [t.strip('"') for t in dmarc if "v=DMARC1" in t]
        if not dmarc:
            yield Finding("infrastructure", "DMARC record missing", confidence=90,
                          notes="No policy telling receivers to reject spoofed mail.")
        for rec in dmarc:
            note = "Policy enforced."
            if "p=none" in rec.replace(" ", ""):
                note = "Policy is p=none, monitor only. Spoofed mail is still delivered."
            yield Finding("infrastructure", f"DMARC: {clip(rec, 200)}", confidence=90, notes=note)

        for t in txt:
            if "v=spf1" not in t:
                yield Finding("infrastructure", f"TXT: {clip(t.strip(chr(34)), 200)}", confidence=80,
                              notes="Often reveals SaaS vendors and verification tokens.")


def _vcard_name(entity):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


@register
class Rdap(Plugin):
    name = "rdap"
    tier = "deep"
    description = "Registrar, name servers and registration dates from RDAP. Netblock owner for IPs."
    categories = ("infrastructure",)
    needs_any = ("domain", "ip")
    order = 20

    def run(self, ctx):
        d, ip = ctx.target.get("domain"), first_ip(ctx.target.get("ip"))
        if d:
            data = ctx.http.get_json(f"https://rdap.org/domain/{d}")
            if data:
                for ent in data.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        name = _vcard_name(ent)
                        if name:
                            yield Finding("infrastructure", f"Registrar: {name}", confidence=95, notes=d)
                for ns in data.get("nameservers", []):
                    if ns.get("ldhName"):
                        yield Finding("infrastructure", f"NS {ns['ldhName'].lower()}", confidence=95, notes="RDAP")
                for ev in data.get("events", []):
                    if ev.get("eventAction") in ("registration", "expiration", "last changed"):
                        yield Finding("infrastructure", f"Domain {ev['eventAction']}: {ev['eventDate'][:10]}",
                                      confidence=95, notes=d)
        if ip:
            data = ctx.http.get_json(f"https://rdap.org/ip/{ip}")
            if data:
                rng = f"{data.get('startAddress', '?')} to {data.get('endAddress', '?')}"
                who = f"{data.get('name', '')} ({data.get('handle', '')}) {data.get('country', '')}".strip()
                yield Finding("infrastructure", f"Netblock {rng}", confidence=95, notes=who)


@register
class CrtSh(Plugin):
    name = "crtsh"
    tier = "deep"
    description = "Subdomains from certificate transparency logs (crt.sh). Finds hosts search engines never indexed."
    categories = ("subdomains",)
    needs_any = ("domain",)
    order = 30

    def run(self, ctx):
        d = ctx.target["domain"]
        rows = ctx.http.get_json(f"https://crt.sh/?q=%25.{d}&output=json", timeout=45) or []
        seen = {}
        for row in rows:
            for n in (row.get("name_value") or "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and n != d and in_domain(n, d) and n not in seen:
                    seen[n] = row.get("issuer_name", "")
        for n, issuer in sorted(seen.items()):
            yield Finding("subdomains", n, confidence=85,
                          notes=f"Seen in certificate transparency logs. Issuer: {clip(issuer, 80)}")


TAKEOVER_HINTS = (
    "github.io", "herokuapp.com", "azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net",
    "s3.amazonaws.com", "s3-website", "cloudfront.net", "elasticbeanstalk.com", "fastly.net",
    "pages.dev", "netlify.app", "wordpress.com", "zendesk.com", "readme.io", "ghost.io", "surge.sh",
)


@register
class ResolveSubdomains(Plugin):
    name = "resolve_subdomains"
    tier = "deep"
    description = "Resolves every subdomain found so far and flags dangling CNAMEs that could be taken over."
    categories = ("infrastructure",)
    needs_any = ("domain",)
    order = 40
    touches_target = True

    def run(self, ctx):
        hosts = [f["value"] for f in ctx.store.findings("subdomains")][: config.MAX_RESOLVE_HOSTS]
        for h in hosts:
            cnames, _ = dns_lookup(h, "CNAME")
            for c in cnames:
                target = c.rstrip(".").lower()
                yield Finding("infrastructure", f"{h} CNAME {target}", confidence=95)
                if any(hint in target for hint in TAKEOVER_HINTS):
                    _, st = dns_lookup(target, "A")
                    if st == "nxdomain":
                        yield Finding("infrastructure", f"Possible subdomain takeover: {h}", confidence=60,
                                      notes=f"CNAME points at {target}, which does not resolve. "
                                            "Check whether the service account is unclaimed.")
            a, _ = dns_lookup(h, "A")
            for ip in a:
                yield Finding("infrastructure", f"{h} A {ip}", confidence=95)


@register
class HttpProbe(Plugin):
    name = "http_probe"
    tier = "deep"
    description = "One GET to the root of each host. Records status, Server and X-Powered-By headers, page title."
    categories = ("tech", "infrastructure")
    needs_any = ("domain", "ip")
    order = 50
    touches_target = True

    def run(self, ctx):
        hosts = []
        if ctx.target.get("domain"):
            hosts.append(ctx.target["domain"])
            hosts += [f["value"] for f in ctx.store.findings("subdomains")]
        ip = ctx.target.get("ip")
        if ip and "/" not in ip:
            hosts.append(ip)
        for h in hosts[: config.MAX_PROBE_HOSTS]:
            info = ctx.http.probe(h)
            if not info:
                continue
            note = f"{info['final_url']}"
            if info.get("title"):
                note += f" | title: {info['title']}"
            yield Finding("infrastructure", f"{h} responds {info['status']} over {info['scheme']}",
                          confidence=95, notes=note)
            for label, key in (("Server", "server"), ("X-Powered-By", "powered_by"), ("X-AspNet-Version", "aspnet")):
                if info.get(key):
                    yield Finding("tech", f"{label}: {info[key]}", confidence=90, notes=f"Seen on {h}")
            blob = " ".join(str(info.get(k) or "") for k in ("title", "server", "powered_by"))
            for name, _ in scan(blob):
                yield Finding("tech", name, confidence=75, notes=f"Banner or title on {h}: {clip(blob, 100)}")


GENERIC_AUTHORS = {"", "microsoft office user", "user", "unknown", "author", "owner"}


def _clean_author(s):
    s = (s or "").strip()
    return None if s.lower() in GENERIC_AUTHORS or len(s) > 40 else s


def _ooxml_meta(data):
    out = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = set(z.namelist())
        for part, tags in (
            ("docProps/core.xml", ("creator", "lastModifiedBy")),
            ("docProps/app.xml", ("Application", "AppVersion", "Company")),
        ):
            if part in names and z.getinfo(part).file_size < 1_000_000:
                root = ET.fromstring(z.read(part))
                for el in root:
                    tag = el.tag.split("}")[-1]
                    if tag in tags and el.text:
                        out[tag] = el.text.strip()
    return out


def _pdf_meta(data):
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        return {}
    md = reader.metadata or {}
    out = {}
    for key, tag in (("/Author", "creator"), ("/Creator", "Application"), ("/Producer", "Producer")):
        if md.get(key):
            out[tag] = str(md.get(key)).strip()
    return out


def extract_metadata(url, data):
    path = url.lower().split("?")[0]
    if path.endswith(".pdf") or data[:5] == b"%PDF-":
        return _pdf_meta(data)
    if path.endswith((".docx", ".xlsx", ".pptx")) or data[:2] == b"PK":
        return _ooxml_meta(data)
    return {}


@register
class DocMetadata(Plugin):
    name = "doc_metadata"
    tier = "deep"
    description = "Downloads documents found on the client's domain and reads author names, usernames and software versions from the metadata."
    categories = ("employees", "tech")
    needs_any = ("domain",)
    order = 60
    touches_target = True

    def run(self, ctx):
        d = ctx.target["domain"]
        urls = [f["value"] for f in ctx.store.findings("documents") if in_domain(hostname(f["value"]), d)]
        for url in urls[: config.MAX_DOCS_PER_RUN]:
            try:
                data = ctx.http.download(url)
                meta = extract_metadata(url, data) if data else {}
            except Exception as e:
                ctx.log(f"skipped {url}: {e}")
                continue
            for key in ("creator", "lastModifiedBy"):
                who = _clean_author(meta.get(key))
                if who:
                    role = "author" if key == "creator" else "last saved by"
                    yield Finding("employees", who, url=url, confidence=60,
                                  notes=f"Document {role}. Often a login name or full name.")
            app = meta.get("Application") or meta.get("Producer")
            if app:
                ver = f" {meta['AppVersion']}" if meta.get("AppVersion") else ""
                yield Finding("tech", f"Document software: {clip(app, 80)}{ver}", url=url, confidence=70,
                              notes="Client desktop software and version, from file metadata.")
            if meta.get("Company"):
                yield Finding("tech", f"Office company name field: {clip(meta['Company'], 80)}", url=url,
                              confidence=50, notes="Organization name stamped into Office files.")
