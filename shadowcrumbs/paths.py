"""Sorts a URL into what it exposes: an open directory, a backup, an admin page, a login portal and so on.

Search results, the Internet Archive and the live probe all use this one list, so a page is called the same
thing whichever way it was found. Only the path and query are looked at, never the host: "dev" in devcorp.com
says nothing about the path.
"""
import re
from urllib.parse import urlparse

# (kind, label, pattern), most serious first: the first match wins
KINDS = [
    ("vcs", "Exposed source control", re.compile(r"/\.(git|svn|hg)(/|$)|/\.gitignore$|/\.DS_Store$", re.I)),
    ("secrets", "Exposed config or secrets", re.compile(
        r"(/\.env(\.[a-z]+)?$|wp-config\.php|/web\.config$|/\.htpasswd$|/\.npmrc$|/\.aws/|id_rsa|\.pem$|\.tfvars$|"
        r"/config\.(php|json|ya?ml|inc)$|/settings\.py$|/application\.(properties|ya?ml)$)", re.I)),
    ("backup", "Exposed backup", re.compile(
        r"(\.(bak|backup|old|orig|sql|sql\.gz|dump|tar|tar\.gz|tgz|rar|7z|swp)$|\.zip$|~$|"
        r"/(backups?|dumps?|db_?backup)(/|$)|(backup|dump|database|db_?export)[^/]*\.(zip|gz|sql|tar|bz2)$)", re.I)),
    ("directory", "Open directory listing", re.compile(r"/(index_of|parent_directory)\b|[?&]C=[NMSD];O=[AD]", re.I)),
    ("debug", "Debug or status page", re.compile(
        r"(phpinfo|/server-status|/server-info|/actuator(/|$)|/_profiler|/debug(/|$)|/elmah\.axd|/trace\.axd|/\.well-known/security)",
        re.I)),
    ("admin", "Admin page", re.compile(
        r"(/wp-admin|/administrator(/|$)|/admin(/|\.|$|\?)|/admin[-_]?(panel|console|area)|/manager/html|/phpmyadmin|/pma(/|$)|"
        r"/cpanel|/webmin|/jenkins|/grafana|/kibana|/solr(/|$)|/console(/|$)|/dashboard(/|$)|/controlpanel|/siteadmin)", re.I)),
    ("login", "Login portal", re.compile(
        r"(/log-?in\b|/log-?on\b|/sign-?in\b|/signon|/sso(/|$)|/auth(/|$)|/oauth|/saml|/owa(/|$)|/remote(/|$)|/vpn(/|$)|"
        r"/portal(/|$)|/webmail|/citrix|/global-protect|/dana-na|/my\.policy|/rdweb|/ecp(/|$)|/account/login|/user/login)", re.I)),
    ("api_docs", "API docs or schema", re.compile(r"(/swagger|/api-docs|/openapi\.(json|ya?ml)|/graphql|/graphiql|/redoc)", re.I)),
    # /.well-known/ files publish how the site is wired: OIDC endpoints, app links, AI plugin manifests, policy files
    ("wellknown", "Well-known metadata file", re.compile(r"/\.well-known/[^/]+", re.I)),
    # sitemaps and feeds list every URL the owner wants found, and often a few they forgot about
    ("discovery", "Sitemap or feed", re.compile(
        r"(/sitemap[^/]*\.xml(\.gz)?$|/robots\.txt$|/(atom|rss|feed|index)\.xml$|/feeds?/[^/]+\.(xml|atom|rss)$|/rss/?$|/feed/?$)", re.I)),
]
LABELS = {k: label for k, label, _ in KINDS}
LABELS["file"] = "Exposed file"
LABELS["data"] = "Data or export file"

# a page title that gives an open directory away even when the URL does not
LISTING_TITLE = re.compile(r"^\s*index of\s*/|^\s*directory listing for\s*/", re.I)
FILE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|csv|txt|log|xml|json|ya?ml|ini|conf|cfg)$", re.I)


def classify(url, title=""):
    """(kind, label) for a URL worth reporting, or None for an ordinary page."""
    try:
        u = urlparse(url)
    except ValueError:
        return None
    where = f"{u.path}?{u.query}" if u.query else u.path
    if LISTING_TITLE.search(title or ""):
        return "directory", LABELS["directory"]
    for kind, label, rx in KINDS:
        if rx.search(where):
            return kind, label
    if FILE_EXT.search(u.path):
        return "file", LABELS["file"]
    return None


def notes_for(kind, how):
    """The note text for a path finding. The kind goes first in brackets so the filter box finds it."""
    return f"[{LABELS[kind]}] {how}"
