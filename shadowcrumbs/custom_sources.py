"""Custom search sources: data points added from the dashboard, no code.

A custom source is data, never code. It is a few searches, a filter and one of a fixed set of ways to turn a
search result into a finding. That is deliberate. Nothing a teammate types here can run as code, fetch a URL
or reach the client, so letting a whole team add sources is safe. Anything that needs more than this is a
plugin file (see tools/new_plugin.py).

The list lives in one JSON file (config.sources_file()). Point SHADOWCRUMBS_SOURCES_FILE at a shared folder or
a git checkout and the team shares it. The file carries a revision number, so two people saving at once get
a clear "someone changed this" instead of one silently overwriting the other.
"""
import json
import os
import re
import tempfile
import threading

from . import config, log
from .plugin import REGISTRY, Finding, Plugin
from .store import clean_person, now
from .util import EMAIL_RE, clip, hostname, in_domain

PREFIX = "custom_"
EXTRACTORS = {
    "title": "Page title (the result's own title, with the link as evidence)",
    "hostname": "Hostname (the site the result is on, needs a domain)",
    "email": "Email addresses found in the result (at the target's domain, needs a domain)",
    "document": "Document link (PDF, Office and similar files only)",
}
NEEDS = ("domain", "company")
MAX_SOURCES, MAX_QUERIES, MAX_KEYWORDS = 100, 10, 10
MAX_QUERY, MAX_LABEL, MAX_DESCRIPTION, MAX_KEYWORD = 300, 60, 200, 60
TOKENS = {"{domain}": "domain", "{d}": "domain", "{company}": "company"}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
LOCK = threading.RLock()
PROBLEMS: list = []          # entries in the file that could not be loaded, shown on the Sources page


class Conflict(Exception):
    """Somebody else saved since this person opened the page."""


# validation ---------------------------------------------------------------------------------------

def _text(value, what, limit, required=True):
    value = value.strip() if isinstance(value, str) else ""
    if not value:
        if required:
            raise ValueError(f"{what} is required")
        return ""
    if CONTROL.search(value):
        raise ValueError(f"{what} cannot contain line breaks or control characters")
    if len(value) > limit:
        raise ValueError(f"{what} is too long (most {limit} characters)")
    return value


def clean(raw, require_author=True):
    """Turn what the form sent into a normalized definition, or raise ValueError saying what is wrong."""
    if not isinstance(raw, dict):
        raise ValueError("a source must be an object")
    label = _text(raw.get("label"), "name", MAX_LABEL)
    category = raw.get("category")
    if category not in config.CATEGORY_KEYS:
        raise ValueError(f"file the findings under one of: {', '.join(config.CATEGORY_KEYS)}")
    wanted = raw.get("needs")
    if not isinstance(wanted, list) or not wanted or any(n not in NEEDS for n in wanted):
        raise ValueError("pick what it needs from the target: domain, company or both")
    needs = [n for n in NEEDS if n in wanted]

    queries = raw.get("queries")
    if not isinstance(queries, list):
        raise ValueError("searches must be a list")
    queries = [q.strip() for q in queries if isinstance(q, str) and q.strip()]
    if not queries:
        raise ValueError("add at least one search")
    if len(queries) > MAX_QUERIES:
        raise ValueError(f"at most {MAX_QUERIES} searches per source, each one is a live query to a search engine")
    for q in queries:
        _text(q, f"search {q[:30]!r}", MAX_QUERY)
        left = q
        for token in TOKENS:
            left = left.replace(token, "")
        if "{" in left or "}" in left:
            raise ValueError(f"search {q[:40]!r}: the only placeholders are {{domain}} and {{company}}")
        for token, field in TOKENS.items():
            if token in q and field not in needs:
                raise ValueError(f"search {q[:40]!r} uses {token} but the source does not need the {field}")

    keywords = raw.get("keywords") or []
    if not isinstance(keywords, list) or len(keywords) > MAX_KEYWORDS:
        raise ValueError(f"keywords must be a list of at most {MAX_KEYWORDS}")
    keywords = [_text(k, "keyword", MAX_KEYWORD).lower() for k in keywords if isinstance(k, str) and k.strip()]

    extractor = raw.get("extractor", "title")
    if extractor not in EXTRACTORS:
        raise ValueError(f"record each result as one of: {', '.join(EXTRACTORS)}")
    only_on_domain = bool(raw.get("only_on_domain"))
    if (only_on_domain or extractor in ("hostname", "email")) and "domain" not in needs:
        raise ValueError("that setting only makes sense when the source needs the domain")
    try:
        confidence = int(raw.get("confidence", 50))
    except (TypeError, ValueError):
        raise ValueError("confidence is a number from 0 to 100") from None
    if not 0 <= confidence <= 100:
        raise ValueError("confidence is a number from 0 to 100")

    author = clean_person(raw.get("author"))
    if require_author and not author:
        raise ValueError("your name is required, so the team knows who made or changed this")
    return {
        "label": label, "description": _text(raw.get("description"), "description", MAX_DESCRIPTION, required=False) or "Custom search source.",
        "category": category, "needs": needs, "queries": queries, "keywords": keywords,
        "only_on_domain": only_on_domain, "extractor": extractor, "confidence": confidence, "author": author,
    }


def slugify(label):
    s = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")[:40].strip("_")
    return s if s and s[0].isalpha() else f"s_{s}".strip("_")


def render_queries(defn, target):
    """The searches this source would send for a target, and the ones it would drop because the target lacks a field."""
    values = {
        "domain": target.get("domain"),
        # a quote inside the company name would end the quoted phrase early and change what the engine searches
        "company": re.sub(r"\s+", " ", (target.get("company") or "").replace('"', " ")).strip(),
    }
    out, dropped = [], []
    for q in defn["queries"]:
        missing = [f for t, f in TOKENS.items() if t in q and not values[f]]
        if missing:
            dropped.append({"query": q, "reason": f"this target has no {missing[0]}"})
            continue
        for token, field in TOKENS.items():
            q = q.replace(token, values[field] or "")
        out.append(q)
    return out, dropped


def estimate_seconds(count):
    return int(count * config.search_delay())


# the plugin ---------------------------------------------------------------------------------------

class CustomSource(Plugin):
    tier = "search"
    custom = True
    order = 60            # after the built-in search sources

    def __init__(self, slug, defn):
        self.slug, self.defn = slug, defn
        self.name = PREFIX + slug
        self.description = defn["description"]
        self.categories = (defn["category"],)
        self.needs_any = tuple(defn["needs"])          # shown in the dashboard; applicable() requires all of them
        self.author = defn["author"]

    def needs_text(self):
        return " and ".join(self.needs_any)

    def applicable(self, target):
        return all(target.get(n) for n in self.defn["needs"])        # every need must be there, not just one

    def run(self, ctx):
        d, spec = ctx.target.get("domain"), self.defn
        queries, _ = render_queries(spec, ctx.target)     # nothing is dropped here: applicable() already needs every field
        seen = set()
        for q in queries:
            for r in ctx.search.search(q):
                text = f"{r.title} {r.snippet} {r.url}".lower()
                if spec["keywords"] and not any(k in text for k in spec["keywords"]):
                    continue
                host = hostname(r.url) or ""
                if spec["only_on_domain"] and d and not in_domain(host, d):
                    continue
                for value, url, notes in self._extract(r, host, d):
                    if value not in seen:
                        seen.add(value)
                        yield Finding(spec["category"], value, url=url, confidence=spec["confidence"], notes=notes)

    def _extract(self, r, host, d):
        kind = self.defn["extractor"]
        if kind == "title":
            yield clip(r.title or r.url, 200), r.url, clip(r.snippet, 200)
        elif kind == "hostname":
            if host and d and in_domain(host, d):
                yield host, r.url, clip(r.title, 120)
        elif kind == "email":
            for m in EMAIL_RE.findall(f"{r.title} {r.snippet}"):
                e = m.lower().strip(".")
                if d and e.split("@", 1)[1].endswith(d):
                    yield e, r.url, clip(r.snippet, 120)
        elif kind == "document":
            from .plugins.search_plugins import doc_ext
            ext = doc_ext(r.url)
            if ext:
                yield r.url, r.url, f"{ext.upper()}: {clip(r.title, 120)}"


# the file -----------------------------------------------------------------------------------------

def _read():
    """(revision, valid entries, invalid raw entries with reasons, file problem). Never raises on a bad file."""
    path = config.sources_file()
    if not path.exists():
        return 0, [], [], None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data["sources"]
        revision = int(data.get("revision", 0))
        if not isinstance(entries, list):
            raise ValueError("'sources' must be a list")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        return 0, [], [], f"{path.name} could not be read ({type(e).__name__}: {e}). It is left alone until you fix or move it."
    good, bad, seen = [], [], set()
    for raw in entries:
        try:
            defn = clean(raw)
            slug = raw.get("slug")
            if not isinstance(slug, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", slug):
                raise ValueError("bad or missing slug")
            if slug in seen:
                raise ValueError(f"duplicate of {slug}")
            seen.add(slug)
            stamp = lambda k: raw.get(k) if isinstance(raw.get(k), str) else None
            good.append({"slug": slug, **defn, "created_at": stamp("created_at"), "updated_at": stamp("updated_at")})
        except (ValueError, AttributeError) as e:
            bad.append((raw, f"{raw.get('label', '?') if isinstance(raw, dict) else '?'}: {e}"))
    return revision, good, bad, None


def _write(revision, good, bad):
    path = config.sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"version": 1, "revision": revision, "sources": good + [b[0] for b in bad]}, indent=2, ensure_ascii=False)
    # the temp file goes next to the target, so the rename stays on one filesystem (a shared drive, say)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".custom_sources_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _writable():
    revision, good, bad, problem = _read()
    if problem:
        raise ValueError(problem)
    return revision, good, bad


def sync():
    """Make the live source list match the file. Called at startup and after every change, so no restart is needed."""
    with LOCK:
        revision, good, bad, problem = _read()
        PROBLEMS[:] = ([problem] if problem else []) + [reason for _, reason in bad]
        for name in [n for n, p in list(REGISTRY.items()) if getattr(p, "custom", False)]:
            REGISTRY.pop(name, None)
        for entry in good:
            plugin = CustomSource(entry["slug"], entry)
            if plugin.name in REGISTRY:
                PROBLEMS.append(f"{entry['label']}: the name {plugin.name} is already taken by another source")
            else:
                REGISTRY[plugin.name] = plugin
    return revision


def snapshot():
    with LOCK:
        revision, good, bad, problem = _read()
        return {
            "revision": revision, "sources": good,
            "problems": ([problem] if problem else []) + [reason for _, reason in bad],
            "extractors": EXTRACTORS, "limits": {"queries": MAX_QUERIES, "keywords": MAX_KEYWORDS},
            "search_delay": config.search_delay(),
        }


def _check_revision(current, expected):
    if expected is not None and int(expected) != current:
        raise Conflict("Someone else changed the sources since you opened this page. Reload to see their changes, then redo yours.")


def _unique_slug(label, taken):
    base = slugify(label)
    slug, n = base, 2
    while slug in taken or (PREFIX + slug) in REGISTRY and not getattr(REGISTRY[PREFIX + slug], "custom", False):
        slug, n = f"{base}_{n}", n + 1
    return slug


def create(raw, expected_revision=None):
    with LOCK:
        revision, good, bad = _writable()
        _check_revision(revision, expected_revision)
        if len(good) >= MAX_SOURCES:
            raise ValueError(f"the list is full ({MAX_SOURCES} sources). Delete one you no longer use")
        defn = clean(raw)
        slug = _unique_slug(defn["label"], {g["slug"] for g in good})
        entry = {"slug": slug, **defn, "created_at": now(), "updated_at": now()}
        _write(revision + 1, good + [entry], bad)
        sync()
    log.logger().getChild("sources").info("custom source created: %s by %r", PREFIX + slug, defn["author"])
    return entry


def update(slug, raw, expected_revision=None):
    with LOCK:
        revision, good, bad = _writable()
        _check_revision(revision, expected_revision)
        old = next((g for g in good if g["slug"] == slug), None)
        if not old:
            raise KeyError(slug)
        defn = clean(raw)
        entry = {"slug": slug, **defn, "created_at": old["created_at"], "updated_at": now()}
        _write(revision + 1, [entry if g["slug"] == slug else g for g in good], bad)
        sync()
    log.logger().getChild("sources").info("custom source updated: %s by %r", PREFIX + slug, defn["author"])
    return entry


def delete(slug, author, expected_revision=None):
    who = clean_person(author)
    if not who:
        raise ValueError("your name is required, so the team knows who made or changed this")
    with LOCK:
        revision, good, bad = _writable()
        _check_revision(revision, expected_revision)
        if not any(g["slug"] == slug for g in good):
            raise KeyError(slug)
        _write(revision + 1, [g for g in good if g["slug"] != slug], bad)
        sync()
    log.logger().getChild("sources").info("custom source deleted: %s by %r", PREFIX + slug, who)


def export():
    revision, good, bad, problem = _read()
    keep = ("label", "description", "category", "needs", "queries", "keywords", "only_on_domain", "extractor", "confidence", "author")
    return {"version": 1, "exported_at": now(), "sources": [{k: g[k] for k in keep} for g in good]}


def import_sources(raw_list, mode="skip", author=None, expected_revision=None):
    """Merge a list of sources, for example one a teammate exported. Every entry goes through the same checks as the form."""
    if mode not in ("skip", "overwrite", "rename"):
        raise ValueError("mode must be skip, overwrite or rename")
    if not isinstance(raw_list, list):
        raise ValueError("sources must be a list")
    importer = clean_person(author)
    if not importer:
        raise ValueError("your name is required, so the team knows who made or changed this")
    imported, skipped = 0, []
    with LOCK:
        revision, good, bad = _writable()
        _check_revision(revision, expected_revision)
        for raw in raw_list[:MAX_SOURCES]:
            label = raw.get("label", "?") if isinstance(raw, dict) else "?"
            try:
                defn = clean({**raw, "author": raw.get("author") or importer} if isinstance(raw, dict) else raw)
            except ValueError as e:
                skipped.append({"label": label, "reason": str(e)})
                continue
            existing = next((g for g in good if g["label"].lower() == defn["label"].lower()), None)
            if existing and mode == "skip":
                skipped.append({"label": label, "reason": "you already have a source with this name"})
                continue
            if existing and mode == "overwrite":
                good = [{**existing, **defn, "updated_at": now()} if g is existing else g for g in good]
            else:
                if len(good) >= MAX_SOURCES:
                    skipped.append({"label": label, "reason": "the list is full"})
                    continue
                if existing:                                            # rename: "Name (2)", "Name (3)", ...
                    n, labels = 2, {g["label"].lower() for g in good}
                    while f"{defn['label'][:MAX_LABEL - 6]} ({n})".lower() in labels:
                        n += 1
                    defn["label"] = f"{defn['label'][:MAX_LABEL - 6]} ({n})"
                good = good + [{"slug": _unique_slug(defn["label"], {g["slug"] for g in good}), **defn,
                                "created_at": now(), "updated_at": now()}]
            imported += 1
        if imported:
            _write(revision + 1, good, bad)
            sync()
    log.logger().getChild("sources").info("custom sources imported: %d by %r, %d skipped", imported, importer, len(skipped))
    return {"imported": imported, "skipped": skipped, "revision": snapshot()["revision"]}
