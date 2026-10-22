"""Reads the text of a downloaded file and picks out what matters: addresses, names and secrets.

Everything here is a pure function on bytes or text, so it is easy to test with hostile input. Nothing is executed,
nothing is rendered. A secret is never handed back whole: find_secrets returns a masked form only, so the full
value cannot reach the database, a log line or an export.
"""
import io
import math
import re
import zipfile
from collections import Counter

from defusedxml import ElementTree as ET

from .util import EMAIL_RE, placeholder_email

TEXT_EXTS = {"txt", "md", "xml", "csv", "json", "log", "yml", "yaml", "ini", "conf", "cfg", "env", "sql", "bak", "properties"}
OFFICE_EXTS = {"docx", "xlsx", "pptx"}
READABLE_EXTS = TEXT_EXTS | OFFICE_EXTS | {"pdf"}

MAX_TEXT_CHARS = 2_000_000
MAX_PDF_PAGES = 50
MAX_UNZIPPED_BYTES = 25 * 1024 * 1024
MAX_ZIP_RATIO = 100             # a normal Office part compresses 5 to 20 times. Past this it is a bomb
MAX_ZIP_PARTS = 2000
SKIPPED_NAMES = ("sitemap", "robots", "crossdomain")     # public by design, nothing in them to find


def extension(url):
    path = url.lower().split("?")[0].split("#")[0]
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1] if "." in name else ""


def readable(url):
    name = url.lower().split("?")[0].rsplit("/", 1)[-1]
    return extension(url) in READABLE_EXTS and not any(name.startswith(s) for s in SKIPPED_NAMES)


# text extraction -------------------------------------------------------

def _plain(data):
    """Decoded text, or None for a binary file. A few stray bytes are fine, a null-heavy file is not text."""
    sample = data[:8192]
    if sample and (sample.count(b"\x00") / len(sample) > 0.01):
        return None
    for enc in ("utf-8", "utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8",):
        try:
            return data.decode(enc)[:MAX_TEXT_CHARS]
        except UnicodeError:
            pass
    return data.decode("latin-1")[:MAX_TEXT_CHARS]


def _xml_text(raw, tags):
    """Text of the given element names (namespace ignored), one per line, from untrusted XML."""
    out = []
    for el in ET.fromstring(raw).iter():
        if el.tag.split("}")[-1] in tags and el.text:
            out.append(el.text)
    return "\n".join(out)


def _office_text(data):
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_PARTS:
            raise ValueError("too many parts in the archive")
        if sum(i.file_size for i in infos) > MAX_UNZIPPED_BYTES:
            raise ValueError("archive expands past the size limit")
        for i in infos:
            if i.compress_size and i.file_size / i.compress_size > MAX_ZIP_RATIO and i.file_size > 1_000_000:
                raise ValueError("archive part compresses suspiciously well")
        names = {i.filename for i in infos}
        wanted = [n for n in names if n == "word/document.xml" or n == "xl/sharedStrings.xml"
                  or re.fullmatch(r"ppt/slides/slide\d+\.xml", n) or re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", n)]
        for n in sorted(wanted):
            with z.open(n) as part:
                raw = part.read(MAX_UNZIPPED_BYTES + 1)
            out.append(_xml_text(raw, {"t", "p"} if n.startswith("word/") else {"t"}))
    return "\n".join(out)[:MAX_TEXT_CHARS]


def _pdf_text(data):
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        return ""
    return "\n".join((p.extract_text() or "") for p in reader.pages[:MAX_PDF_PAGES])[:MAX_TEXT_CHARS]


def extract_text(url, data):
    """The readable text of a file, or None when it is binary or a kind we do not read. Raises on a broken or hostile file."""
    ext = extension(url)
    if ext == "pdf" or data[:5] == b"%PDF-":
        return _pdf_text(data)
    if ext in OFFICE_EXTS or (data[:2] == b"PK" and ext not in TEXT_EXTS):
        return _office_text(data)
    if ext in TEXT_EXTS:
        return _plain(data)
    return None


# secrets ---------------------------------------------------------------

# (label, pattern, group holding the secret, hide it completely)
SECRET_RULES = [
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), 0, True),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, False),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0, False),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0, False),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0, False),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), 0, False),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0, False),
    ("Password in a URL", re.compile(r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"<>]{1,64}:([^\s@/'\"<>]{3,100})@[^\s/'\"<>]+", re.I), 1, False),
    ("Password in XML", re.compile(r"<(pass(?:word|wd)?|pwd|secret|api-?key)>([^<]{3,100})</\1>", re.I), 2, False),
    ("Password or secret", re.compile(
        r"""(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_.-])*(pass(?:word|wd)?|pwd|secret|client[_-]?secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token)\b["']?(\s*[:=]\s*)["']?([^\s"',;<>]{4,100})""",
        re.I), 3, False),
]

PLACEHOLDER = re.compile(
    r"""^(?:[*x•.\-_#]+|<.*>|\{.*\}|\$\{.*\}|%.*%|\[.*\]|your.*|example.*|sample.*|redacted|changeit|none|null|true|false|
    password|passwd|secret|string|value|token|key|username|user|required|optional|enter.*|type.*|must.*|should.*)$""",
    re.I | re.X)


def entropy(s):
    counts = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask(secret):
    """Enough to recognise the value, not enough to use it. The middle is never kept."""
    if len(secret) >= 12:
        return f"{secret[:2]}…{secret[-2:]} ({len(secret)} chars)"
    return f"{len(secret)} chars"


def find_secrets(text, limit=25):
    """[(label, masked, line_number, confidence)] for secrets in the text. The secret itself is never returned."""
    found, seen = [], set()
    for label, rx, group, hide in SECRET_RULES:
        for m in rx.finditer(text):
            if len(found) >= limit:
                return found
            secret = m.group(group)
            conf = 85
            if label == "Password or secret":
                # prose like "Password: must be 8 characters" is noise. Keep values that look chosen by someone.
                if PLACEHOLDER.match(secret):
                    continue
                strong = bool(re.search(r"[\d\W_]", secret)) or entropy(secret) >= 3.5
                if not strong:
                    if m.group(2).strip() != "=":
                        continue
                    conf = 55
                else:
                    conf = 75
            elif label in ("Password in a URL", "Password in XML") and PLACEHOLDER.match(secret):
                continue
            line = text.count("\n", 0, m.start()) + 1
            key = (label, secret)
            if key in seen:
                continue
            seen.add(key)
            found.append((label, "" if hide else mask(secret), line, conf))
    return found


# addresses and names ---------------------------------------------------

def find_emails(text, domain, limit=100):
    """Addresses at the target's domain (or under it), lower cased, placeholders left out."""
    out = []
    for m in EMAIL_RE.findall(text):
        addr = m.lower().rstrip(".")
        host = addr.rsplit("@", 1)[-1]
        if (host == domain or host.endswith("." + domain)) and addr not in out and not placeholder_email(addr, True):
            out.append(addr)
            if len(out) >= limit:
                break
    return out


NAME_WORD = r"[A-Z][a-z]+(?:['’\-][A-Z][a-z]+)?"
NAME_RE = re.compile(rf"^{NAME_WORD}(?: [A-Z]\.?)?(?: {NAME_WORD}){{1,2}}$")
NOT_NAMES = {"team", "department", "dept", "support", "services", "service", "inc", "llc", "ltd", "corp", "corporation",
             "company", "group", "customer", "dear", "all", "staff", "management", "office", "administrator", "admin",
             "help", "desk", "security", "confidential", "internal", "draft", "document", "report", "page", "version"}
LABELLED = re.compile(r"^\s*(?:author|created by|prepared by|reviewed by|approved by|submitted by|owner|contact|"
                      r"point of contact|poc|manager|name|from|to|cc)\s*[:\-]\s*(.{3,80})$", re.I | re.M)
DISPLAY_ADDR = re.compile(r"([A-Za-z][A-Za-z.'’\- ,]{2,50}?)\s*<[^<>\s@]+@[^<>\s]+>")
SIGN_OFF = re.compile(r"^\s*(?:regards|best regards|kind regards|thanks|thank you|sincerely|best|cheers)[,.!]?\s*$", re.I)


def _as_name(raw):
    s = re.sub(r"\s+", " ", raw).strip(" \"'")
    if "," in s:                                   # "Doe, Jane"
        last, _, first = s.partition(",")
        s = f"{first.strip()} {last.strip()}"
    if not NAME_RE.match(s) or any(w.lower().strip(".") in NOT_NAMES for w in s.split()):
        return None
    return s


def find_names(text, limit=50):
    """People named in structured places only: Author:/From:/Contact: labels, 'Name <address>' headers and
    the line under a sign-off. Free text is not searched, which keeps the false positives down."""
    names = []

    def add(raw):
        n = _as_name(raw)
        if n and n not in names and len(names) < limit:
            names.append(n)

    for m in LABELLED.finditer(text):
        value = re.sub(r"<[^>]*>", "", m.group(1)).split(";")[0].split("(")[0]
        add(value)
    for m in DISPLAY_ADDR.finditer(text):
        add(m.group(1))
    lines = text.splitlines()
    for i, line in enumerate(lines[:-1]):
        if SIGN_OFF.match(line):
            add(lines[i + 1])
    return names
