"""Small helpers shared by the core and the plugins."""
import ipaddress
import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,62}$")

ROLE_MAILBOXES = {
    "info", "sales", "support", "admin", "contact", "hr", "careers", "press", "help",
    "noreply", "no-reply", "security", "webmaster", "abuse", "office", "marketing",
    "billing", "jobs", "media", "privacy", "legal", "postmaster",
}


def normalize_domain(value):
    if not value or not value.strip():
        return None
    s = value.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    if s.startswith("www."):
        s = s[4:]
    if not HOST_RE.match(s):
        raise ValueError(f"not a valid domain: {value!r}")
    return s


def normalize_ip(value):
    if not value or not value.strip():
        return None
    s = value.strip()
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False))
        return str(ipaddress.ip_address(s))
    except ValueError:
        raise ValueError(f"not a valid IP address or CIDR range: {value!r}") from None


def first_ip(value):
    """RDAP wants one address. For a CIDR range use the first host."""
    if not value:
        return None
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=False).network_address)
    return value


def hostname(url):
    try:
        return (urlparse(url).hostname or "").lower() or None
    except ValueError:
        return None


def in_domain(host, domain):
    return bool(host) and (host == domain or host.endswith("." + domain))


def guess_company(domain):
    if not domain:
        return None
    parts = domain.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    return label.replace("-", " ").title()


def clip(text, n=160):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def window(text, start, end, pad=70):
    return clip(text[max(0, start - pad): end + pad], 2 * pad + (end - start) + 4)


def email_format(emails, domain):
    """Guess the address format from harvested addresses. Returns (label, hits, total) or None."""
    locals_ = [e.split("@")[0] for e in emails if e.split("@")[0] not in ROLE_MAILBOXES]
    if len(locals_) < 2:
        return None
    patterns = (
        ("first.last", re.compile(r"^[a-z]+\.[a-z]+$")),
        ("first_last", re.compile(r"^[a-z]+_[a-z]+$")),
    )
    for label, rx in patterns:
        hits = sum(1 for l in locals_ if rx.match(l))
        if hits >= 2 and hits / len(locals_) >= 0.5:
            return label, hits, len(locals_)
    return None
