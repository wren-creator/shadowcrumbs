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


def search_backoff() -> list[float]:
    """Seconds to cool off after each consecutive throttle, in order. Empty or 0 turns retrying off."""
    raw = os.environ.get("SHADOWCRUMBS_BACKOFF", "60,120,240")
    return [float(x) for x in raw.split(",") if x.strip() and float(x) > 0]


def http_timeout() -> float:
    return float(os.environ.get("SHADOWCRUMBS_HTTP_TIMEOUT", "15"))


def search_provider(tier: str) -> str:
    """Search tier uses the search engine. Deep tier prefers an API when a key exists."""
    forced = os.environ.get("SHADOWCRUMBS_SEARCH")
    if forced:
        return forced
    if tier == "deep" and os.environ.get("BRAVE_API_KEY"):
        return "brave"
    return "ddg"
