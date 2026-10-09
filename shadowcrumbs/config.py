"""Settings. Everything is read at call time so tests and env overrides just work."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CATEGORIES = [
    ("employees", "Employees"),
    ("emails", "Emails and Credentials"),
    ("documents", "Exposed Documents"),
    ("tech", "Tech Stack"),
    ("subdomains", "Subdomains"),
    ("infrastructure", "Infrastructure"),
]
CATEGORY_KEYS = [k for k, _ in CATEGORIES]

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
MAX_DOCS_PER_RUN = 25
MAX_PROBE_HOSTS = 60
MAX_RESOLVE_HOSTS = 200


def data_dir() -> Path:
    return Path(os.environ.get("SHADOWCRUMBS_DATA", ROOT / "data"))


def engagements_dir() -> Path:
    d = data_dir() / "engagements"
    d.mkdir(parents=True, exist_ok=True)
    return d


def user_plugins_dir() -> Path:
    return Path(os.environ.get("SHADOWCRUMBS_PLUGINS", ROOT / "plugins_user"))


def user_agent() -> str:
    return os.environ.get(
        "SHADOWCRUMBS_UA",
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    )


def search_delay() -> float:
    return float(os.environ.get("SHADOWCRUMBS_SEARCH_DELAY", "8"))


def block_minutes() -> float:
    """How long to stay quiet after a search engine throttles us. DuckDuckGo blocks have run an hour or more."""
    return float(os.environ.get("SHADOWCRUMBS_BLOCK_MINUTES", "60"))


def block_marker() -> Path:
    """Remembers when the search engine last blocked this machine. It is about the IP, so it is not per engagement."""
    return data_dir() / "search_blocked.json"


def http_timeout() -> float:
    return float(os.environ.get("SHADOWCRUMBS_HTTP_TIMEOUT", "15"))


def searxng_url() -> str:
    return os.environ.get("SHADOWCRUMBS_SEARXNG_URL", "").strip()


def search_provider(tier: str) -> str:
    """Search tier uses the search engine. Deep tier prefers an API when a key exists."""
    forced = os.environ.get("SHADOWCRUMBS_SEARCH")
    if forced:
        return forced
    if searxng_url():
        return "searxng"
    if tier == "deep" and os.environ.get("BRAVE_API_KEY"):
        return "brave"
    return "ddg"


def allowed_hosts() -> set[str]:
    """Host names this server answers to. A page on another site that rebinds its DNS to 127.0.0.1 still
    sends its own name in the Host header, so refusing unknown names shuts that attack out.
    Add more (a reverse proxy name, say) with SHADOWCRUMBS_ALLOWED_HOSTS=name1,name2."""
    extra = os.environ.get("SHADOWCRUMBS_ALLOWED_HOSTS", "")
    return {"127.0.0.1", "localhost", "::1"} | {h.strip().lower() for h in extra.split(",") if h.strip()}
