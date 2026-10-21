"""Logging for troubleshooting scans, and the one place secrets get scrubbed out of anything we record.

Two sinks share this module. The rotating file under data/logs/ is for the app as a whole. The run events kept in
each engagement database (see Store.add_event) are for one scan. Both pass through redact(), so a key cannot
reach either one by a path nobody thought of. We log the method, the URL, the status and the timing, never
request headers or bodies.

Timestamps are UTC everywhere, so a log line lines up with a run in the dashboard.

Logs name the targets and queries, so they are as client confidential as the engagement databases. They live
under data/, which is gitignored.
"""
import logging
import os
import re
import time
from logging.handlers import RotatingFileHandler
from urllib.parse import urlsplit, urlunsplit

from . import config

NAME = "shadowcrumbs"
FILE_NAME = "shadowcrumbs.log"
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASS|AUTH|CRED)", re.I)
SENSITIVE_PARAM = r"(?:[a-z0-9_.-]*(?:key|token|secret|passw(?:or)?d|auth|sig(?:nature)?|credential)[a-z0-9_.-]*)"
QUERY_SECRET = re.compile(rf"(?i)\b({SENSITIVE_PARAM})=([^&\s\"'<>]+)")
AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-[a-z-]*(?:key|token))\s*[:=]\s*[^\r\n]+")
BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}")
USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
MASK = "***"


def _secret_values():
    """The literal values of secret-looking environment variables, longest first so a short one cannot cut a long one."""
    vals = {v for k, v in os.environ.items() if SECRET_ENV.search(k) and len(v) >= 6}
    return sorted(vals, key=len, reverse=True)


def redact(text):
    """Mask anything that looks like a credential. Safe to call on any string, repeatedly."""
    if not text:
        return text
    text = str(text)
    for v in _secret_values():
        text = text.replace(v, MASK)
    text = USERINFO.sub(r"\1" + MASK + "@", text)
    text = AUTH_HEADER.sub(lambda m: f"{m.group(1)}: {MASK}", text)
    text = BEARER.sub(lambda m: f"{m.group(1)} {MASK}", text)
    return QUERY_SECRET.sub(lambda m: f"{m.group(1)}={MASK}", text)


def safe_url(url):
    """A URL fit for a log: no credentials in the host part, no fragment, secret-looking query values masked."""
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        if parts.port:
            host += f":{parts.port}"
        return redact(urlunsplit((parts.scheme, host, parts.path, parts.query, "")))
    except ValueError:
        return redact(url)


class RedactingFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        if record.exc_info:                      # fold the traceback into the message so it is scrubbed too
            record.msg += "\n" + redact(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True


def file_path():
    return config.logs_dir() / FILE_NAME


def logger():
    """The app logger, with its file handler pointed at the current data directory."""
    log = logging.getLogger(NAME)
    log.setLevel(getattr(logging, config.log_level(), logging.INFO))
    log.propagate = False
    want = str(file_path())
    have = [h for h in log.handlers if isinstance(h, RotatingFileHandler)]
    if not have or have[0].baseFilename != want:
        for h in have:
            log.removeHandler(h)
            h.close()
        h = RotatingFileHandler(want, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s", "%Y-%m-%d %H:%M:%S")
        fmt.converter = time.gmtime          # UTC, the same clock as the engagement databases
        h.setFormatter(fmt)
        h.addFilter(RedactingFilter())
        log.addHandler(h)
    return log


LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}


def tail(lines=300, level=None):
    """The last lines of the app log, oldest first, optionally only at or above a level."""
    path = file_path()
    if not path.exists():
        return []
    lines = max(1, min(int(lines), 2000))
    with open(path, "rb") as f:                  # read from the end, the file can be 2 MB
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - 400_000))
        raw = f.read().decode("utf-8", "replace").splitlines()
    floor = LEVELS.get((level or "").lower(), 0)
    out, keep = [], True
    for line in raw:
        m = re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d (\w+)", line)
        if m:
            keep = LEVELS.get(m.group(1).lower().replace("warn", "warning"), 20) >= floor
        if keep:
            out.append(line)
    return out[-lines:]
