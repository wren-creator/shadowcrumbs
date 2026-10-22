"""One SQLite file per engagement. Nothing is shared between clients."""
import json
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config
from .log import logger, redact
from .util import in_domain, normalize_domain, normalize_ip

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  value TEXT NOT NULL,
  plugins TEXT NOT NULL DEFAULT '',
  tier TEXT NOT NULL DEFAULT 'search',
  url TEXT,
  confidence INTEGER NOT NULL DEFAULT 50,
  notes TEXT,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  UNIQUE(category, value)
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  plugin TEXT NOT NULL,
  tier TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  found INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE TABLE IF NOT EXISTS authorizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  auth_ref TEXT NOT NULL DEFAULT '',
  recorded_by TEXT NOT NULL,
  recorded_at TEXT
);
CREATE TABLE IF NOT EXISTS scope_domains (
  domain TEXT PRIMARY KEY,
  added_by TEXT NOT NULL,
  added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER,
  at TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS search_cache (
  query TEXT PRIMARY KEY,
  results TEXT NOT NULL,
  cached_at REAL NOT NULL
);
"""

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*$")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


UNSPECIFIED = "unspecified"


def clean_person(name):
    """The name of whoever records an authorization. One line, no control characters, 80 characters at most."""
    name = re.sub(r"[\x00-\x1f\x7f]+", " ", name or "")
    return re.sub(r"\s+", " ", name).strip()[:80]


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return s[:60].strip("-") or "engagement"


def audit_log(slug, action, ref, by):
    """Every ROE change also goes to the app log. The per-engagement table is a convenience, not forensics:
    anyone who can write to the .db file can change it, and it is deleted with the engagement."""
    logger().getChild("audit").info("ROE %s: engagement=%s ref=%r by=%r", action, slug, ref, by)


def list_slugs():
    return sorted(p.stem for p in config.engagements_dir().glob("*.db"))


class Store:
    def __init__(self, slug):
        if not SLUG_RE.match(slug or ""):
            raise KeyError(slug)
        self.slug = slug
        self.path = config.engagements_dir() / f"{slug}.db"
        if not self.path.exists():
            raise KeyError(slug)
        self._ensure_schema()

    def _ensure_schema(self):
        """Engagements made before a table existed get it on first open. Existing ROE state is backfilled once,
        with no invented name or time: the old database never recorded either."""
        c = sqlite3.connect(self.path, timeout=30)
        try:
            c.executescript(SCHEMA)
            m = dict(c.execute("SELECT key, value FROM meta"))
            if m.get("authorized") == "1" and not c.execute("SELECT 1 FROM authorizations LIMIT 1").fetchone():
                c.execute(
                    "INSERT INTO authorizations(action, auth_ref, recorded_by, recorded_at) VALUES ('granted', ?, ?, NULL)",
                    (m.get("auth_ref", ""), "unknown (recorded before the audit trail)"),
                )
            c.commit()
        finally:
            c.close()

    # creation ---------------------------------------------------------

    @classmethod
    def create(cls, name, company=None, domain=None, ip=None, auth_ref=None, authorized=False,
               authorized_by=None, require_name=False):
        name = (name or "").strip()
        if not name:
            raise ValueError("engagement name is required")
        company = (company or "").strip() or None
        domain = normalize_domain(domain)
        ip = normalize_ip(ip)
        if not (company or domain or ip):
            raise ValueError("give at least one of company, domain, or IP")
        auth_ref = (auth_ref or "").strip() or None
        if authorized and not auth_ref:
            raise ValueError("an authorization reference is required to mark a target authorized")
        by = clean_person(authorized_by)
        if authorized and require_name and not by:
            raise ValueError("the name of the person recording this authorization is required")

        base = slugify(name)
        slug, n = base, 2
        while (config.engagements_dir() / f"{slug}.db").exists():
            slug, n = f"{base}-{n}", n + 1
        path = config.engagements_dir() / f"{slug}.db"
        c = sqlite3.connect(path)
        try:
            c.executescript(SCHEMA)
            rows = {
                "name": name, "company": company or "", "domain": domain or "", "ip": ip or "",
                "authorized": "1" if authorized else "0", "auth_ref": auth_ref or "",
                "notes": "", "created_at": now(),
            }
            c.executemany("INSERT INTO meta(key, value) VALUES (?, ?)", rows.items())
            if authorized:
                c.execute(
                    "INSERT INTO authorizations(action, auth_ref, recorded_by, recorded_at) VALUES ('granted', ?, ?, ?)",
                    (auth_ref, by or UNSPECIFIED, now()),
                )
            c.commit()
        finally:
            c.close()
        store = cls(slug)
        if authorized:
            audit_log(slug, "granted", auth_ref, by or UNSPECIFIED)
        return store

    # plumbing ---------------------------------------------------------

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            c.execute("PRAGMA journal_mode=WAL")
            yield c
            c.commit()
        finally:
            c.close()

    def delete_files(self):
        for suffix in ("", "-wal", "-shm"):
            p = self.path.with_name(self.path.name + suffix)
            if p.exists():
                p.unlink()

    # meta -------------------------------------------------------------

    def meta(self):
        with self.conn() as c:
            m = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM meta")}
        return {
            "slug": self.slug,
            "name": m.get("name", self.slug),
            "company": m.get("company") or None,
            "domain": m.get("domain") or None,
            "ip": m.get("ip") or None,
            "authorized": m.get("authorized") == "1",
            "auth_ref": m.get("auth_ref") or None,
            "notes": m.get("notes", ""),
            "created_at": m.get("created_at"),
            "last_authorization": self.authorizations(last=True),
            "scope_domains": self.scope_domains(),
        }

    def update_meta(self, authorized=None, auth_ref=None, notes=None, authorized_by=None, require_name=False):
        current = self.meta()
        ref = current["auth_ref"] if auth_ref is None else (auth_ref.strip() or None)
        is_auth = current["authorized"] if authorized is None else bool(authorized)
        if is_auth and not ref:
            raise ValueError("an authorization reference is required to mark a target authorized")
        changed = (is_auth, ref or "") != (current["authorized"], current["auth_ref"] or "")
        by = clean_person(authorized_by)
        if changed and require_name and not by:
            raise ValueError("the name of the person recording this change is required")
        updates = {"authorized": "1" if is_auth else "0", "auth_ref": ref or ""}
        if notes is not None:
            updates["notes"] = notes
        with self.conn() as c:
            c.executemany("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", updates.items())
            if changed:
                action = "granted" if is_auth and not current["authorized"] else "revoked" if current["authorized"] and not is_auth else "updated"
                c.execute(
                    "INSERT INTO authorizations(action, auth_ref, recorded_by, recorded_at) VALUES (?, ?, ?, ?)",
                    (action, ref or "", by or UNSPECIFIED, now()),
                )
        if changed:
            audit_log(self.slug, action, ref or "", by or UNSPECIFIED)

    def authorizations(self, last=False):
        """The ROE history, oldest first. Append only: nothing in the app edits or removes a row."""
        with self.conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM authorizations ORDER BY id")]
        return (rows[-1] if rows else None) if last else rows

    def scope_domains(self):
        """Subdomains the operator pulled into scope, oldest first. Each is a host under the engagement's own domain."""
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT domain, added_by, added_at FROM scope_domains ORDER BY added_at, domain")]

    def add_scope_domain(self, domain, added_by):
        """Pull a subdomain of the engagement's domain into scope so it can be scanned too. Adding one twice is a no-op."""
        primary = self.meta()["domain"]
        if not primary:
            raise ValueError("this engagement has no domain, so there is nothing to add a subdomain of")
        domain = normalize_domain(domain)
        if not domain:
            raise ValueError("give the subdomain to add")
        if domain == primary:
            raise ValueError(f"{domain} is already the engagement's main domain")
        if not in_domain(domain, primary):
            raise ValueError(f"{domain} is not under {primary}. Only subdomains of the engagement's domain can be added.")
        by = clean_person(added_by)
        if not by:
            raise ValueError("the name of the person adding this to scope is required")
        with self.conn() as c:
            cur = c.execute("INSERT OR IGNORE INTO scope_domains(domain, added_by, added_at) VALUES (?, ?, ?)",
                            (domain, by, now()))
            added = cur.rowcount > 0
        if added:
            logger().getChild("audit").info("scope add: engagement=%s domain=%s by=%r", self.slug, domain, by)
        return domain

    def remove_scope_domain(self, domain, removed_by=None):
        with self.conn() as c:
            cur = c.execute("DELETE FROM scope_domains WHERE domain=?", ((domain or "").strip().lower(),))
            if cur.rowcount == 0:
                raise KeyError(domain)
        logger().getChild("audit").info("scope remove: engagement=%s domain=%s by=%r", self.slug, domain,
                                        clean_person(removed_by) or UNSPECIFIED)

    def counts(self):
        with self.conn() as c:
            rows = c.execute("SELECT category, COUNT(*) AS n FROM findings GROUP BY category").fetchall()
        out = {k: 0 for k in config.CATEGORY_KEYS}
        out.update({r["category"]: r["n"] for r in rows})
        return out

    # findings ---------------------------------------------------------

    def add_finding(self, category, value, plugin, tier, url=None, confidence=50, notes=None):
        """Insert a finding. Returns True when it is new, False when it was already known."""
        if category not in config.CATEGORY_KEYS:
            raise ValueError(f"unknown category {category!r}")
        value = (value or "").strip()[:500]
        if not value:
            raise ValueError("empty finding value")
        confidence = max(0, min(100, int(confidence)))
        notes = (notes or "")[:1000] or None
        with self.conn() as c:
            row = c.execute(
                "SELECT id, plugins, url FROM findings WHERE category=? AND value=?", (category, value)
            ).fetchone()
            if row:
                plugins = [p for p in row["plugins"].split(",") if p]
                if plugin not in plugins:
                    plugins.append(plugin)
                c.execute(
                    "UPDATE findings SET plugins=?, url=COALESCE(url, ?) WHERE id=?",
                    (",".join(plugins), url, row["id"]),
                )
                return False
            c.execute(
                "INSERT INTO findings(category, value, plugins, tier, url, confidence, notes, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (category, value, plugin, tier, url, confidence, notes, now()),
            )
            return True

    def findings(self, category=None):
        sql = "SELECT * FROM findings"
        args = ()
        if category:
            sql += " WHERE category=?"
            args = (category,)
        sql += " ORDER BY category, confidence DESC, value COLLATE NOCASE"
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(sql, args)]
        for r in rows:
            r["plugins"] = [p for p in r["plugins"].split(",") if p]
            r["verified"] = bool(r["verified"])
        return rows

    def update_finding(self, fid, notes=None, verified=None, confidence=None):
        sets, args = [], []
        if notes is not None:
            sets.append("notes=?")
            args.append(notes[:1000])
        if verified is not None:
            sets.append("verified=?")
            args.append(1 if verified else 0)
        if confidence is not None:
            sets.append("confidence=?")
            args.append(max(0, min(100, int(confidence))))
        if not sets:
            return
        with self.conn() as c:
            cur = c.execute(f"UPDATE findings SET {', '.join(sets)} WHERE id=?", (*args, fid))
            if cur.rowcount == 0:
                raise KeyError(fid)

    def delete_finding(self, fid):
        with self.conn() as c:
            cur = c.execute("DELETE FROM findings WHERE id=?", (fid,))
            if cur.rowcount == 0:
                raise KeyError(fid)

    # runs -------------------------------------------------------------

    def start_run(self, plugin, tier):
        with self.conn() as c:
            cur = c.execute(
                "INSERT INTO runs(plugin, tier, started_at, status) VALUES (?, ?, ?, 'running')",
                (plugin, tier, now()),
            )
            return cur.lastrowid

    def finish_run(self, run_id, status, found, error=None):
        with self.conn() as c:
            c.execute(
                "UPDATE runs SET finished_at=?, status=?, found=?, error=? WHERE id=?",
                (now(), status, found, (error or None) and error[:500], run_id),
            )

    def runs(self, limit=200):
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    # run events -------------------------------------------------------
    # A readable trail of what each scan did, for troubleshooting. Everything is redacted on the way in.

    def add_event(self, run_id, level, message):
        level = level if level in ("debug", "info", "warning", "error") else "info"
        with self.conn() as c:
            c.execute(
                "INSERT INTO run_events(run_id, at, level, message) VALUES (?, ?, ?, ?)",
                (run_id, now(), level, redact(message)[:4000]),
            )

    def events(self, run_id=None, level=None, limit=500):
        """The most recent events, oldest first. `level` is a floor: warning returns warnings and errors."""
        floors = {"debug": 0, "info": 1, "warning": 2, "error": 3}
        order = ["debug", "info", "warning", "error"]
        wanted = order[floors.get(level or "debug", 0):]
        sql = f"SELECT * FROM run_events WHERE level IN ({','.join('?' * len(wanted))})"
        args = list(wanted)
        if run_id is not None:
            sql += " AND run_id=?"
            args.append(run_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 5000)))
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(sql, args)]
        return rows[::-1]

    def prune_events(self, keep=5000):
        """Called once per run, not per insert, so a busy scan does not pay for it on every line."""
        with self.conn() as c:
            c.execute("DELETE FROM run_events WHERE id <= (SELECT COALESCE(MAX(id), 0) - ? FROM run_events)", (keep,))

    # search cache -----------------------------------------------------

    def cache_get(self, query, ttl):
        with self.conn() as c:
            row = c.execute("SELECT results, cached_at FROM search_cache WHERE query=?", (query,)).fetchone()
        if row and time.time() - row["cached_at"] <= ttl:
            return json.loads(row["results"])
        return None

    def cache_put(self, query, results):
        with self.conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO search_cache(query, results, cached_at) VALUES (?, ?, ?)",
                (query, json.dumps(results), time.time()),
            )
