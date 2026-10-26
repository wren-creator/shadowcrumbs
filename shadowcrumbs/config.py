"""Settings. Everything is read at call time so tests and env overrides just work."""
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CATEGORIES = [
    ("employees", "Employees"),
    ("emails", "Emails and Credentials"),
    ("documents", "Exposed Documents"),
    ("tech", "Tech Stack"),
    ("subdomains", "Subdomains"),
    ("infrastructure", "Infrastructure"),
    ("exposures", "Exposed Paths and Files"),
]
CATEGORY_KEYS = [k for k, _ in CATEGORIES]

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
MAX_DOCS_PER_RUN = 25
MAX_PROBE_HOSTS = 60
MAX_RESOLVE_HOSTS = 200
MAX_BRUTE_WORDS = 2000
MAX_SPIDER_PAGES = 200
MAX_SPIDER_PAGES_PER_HOST = 30
MAX_SPIDER_DEPTH = 2
MAX_PORTSCAN_IPS = 20
MAX_PORTS = 200


def data_dir() -> Path:
    return Path(os.environ.get("SHADOWCRUMBS_DATA", ROOT / "data"))


def engagements_dir() -> Path:
    d = data_dir() / "engagements"
    d.mkdir(parents=True, exist_ok=True)
    return d


def sources_file() -> Path:
    """Where the custom search sources made in the dashboard are kept. Point it at a shared folder (or a git
    checkout) and the whole team uses one list."""
    raw = os.environ.get("SHADOWCRUMBS_SOURCES_FILE", "").strip()
    return Path(raw).expanduser() if raw else data_dir() / "custom_sources.json"


def logs_dir() -> Path:
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_level() -> str:
    """INFO records lifecycle, searches and failures. DEBUG adds every HTTP request and cache hit."""
    return os.environ.get("SHADOWCRUMBS_LOG_LEVEL", "INFO").strip().upper() or "INFO"


def personal_plugin_dirs() -> list[Path]:
    """Extra plugin folders kept outside this repo (private tools). Separate with the OS path separator."""
    raw = os.environ.get("SHADOWCRUMBS_PERSONAL_PLUGINS", "")
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]


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


def search_chain(tier: str) -> list[str]:
    """Search engines to try, best first. A throttle on one moves on to the next instead of ending the run.
    Brave (an API, so no CAPTCHAs) then your own SearXNG, then DuckDuckGo, then Exa. Exa goes last on purpose:
    it is a free account with a credit limit, so it only spends credits on what the others could not answer.
    SHADOWCRUMBS_SEARCH forces exactly one and turns the fallback off."""
    forced = os.environ.get("SHADOWCRUMBS_SEARCH")
    if forced:
        return [forced]
    chain = []
    if os.environ.get("BRAVE_API_KEY"):
        chain.append("brave")
    if searxng_url():
        chain.append("searxng")
    chain.append("ddg")
    if os.environ.get("EXA_API_KEY"):
        chain.append("exa")
    return chain


def search_balance() -> bool:
    """Spread queries across the engines in the chain instead of always asking the first one that is up.
    Off unless SHADOWCRUMBS_SEARCH_BALANCE is 1, true, yes or on: with a Brave key the strict order is the faster scan."""
    return os.environ.get("SHADOWCRUMBS_SEARCH_BALANCE", "").strip().lower() in ("1", "true", "yes", "on")


# Shares of the traffic when balancing. A weight of 0 keeps an engine in reserve: asked only when every engine with
# a share is down. DuckDuckGo throttles hard and Exa is a free account with a credit limit, so both start in reserve.
# Brave leads: it costs about half a cent a query and its answers stay on the site asked for (2026-10-22: 39 of 39
# results on site, against 4 of 21 through SearXNG from this network), so it is not worth sparing.
DEFAULT_WEIGHTS = {"brave": 3, "searxng": 2, "ddg": 0, "exa": 0}


def search_weight(name: str) -> float:
    """SHADOWCRUMBS_SEARCH_WEIGHTS="brave=3,searxng=1,ddg=1" changes the shares. A part that is not name=number, or a
    negative number, is ignored. An engine that is not listed anywhere gets a share of 1."""
    weights = dict(DEFAULT_WEIGHTS)
    for part in os.environ.get("SHADOWCRUMBS_SEARCH_WEIGHTS", "").split(","):
        key, sep, val = part.partition("=")
        try:
            if sep and float(val) >= 0:
                weights[key.strip().lower()] = float(val)
        except ValueError:
            continue
    return weights.get(name, 1.0)


def engine_cooldown() -> float:
    """Seconds a throttled engine sits out before it rejoins the rotation. A refused key or used up credits do not
    come back during a run, and neither does DuckDuckGo, which has its own longer memory (block_minutes)."""
    return float(os.environ.get("SHADOWCRUMBS_ENGINE_COOLDOWN", "300"))


def search_provider(tier: str) -> str:
    """The engine tried first."""
    return search_chain(tier)[0]


KEY_NAMES = ("BRAVE_API_KEY", "GITHUB_TOKEN", "HIBP_API_KEY", "DEHASHED_API_KEY", "URLSCAN_API_KEY", "EXA_API_KEY")


def env_file() -> Path:
    raw = os.environ.get("SHADOWCRUMBS_ENV_FILE", "").strip()
    return Path(raw).expanduser() if raw else ROOT / ".env"


def load_env_file() -> tuple[list[str], str | None]:
    """Read KEY=value lines from .env into the environment, so keys stay out of shell history and profiles.
    Returns (names loaded, a problem or None). Never returns or logs a value.
    Refuses a file other users can read: chmod 600 .env. A variable already set in the environment wins."""
    path = env_file()
    try:
        st = path.stat()
    except FileNotFoundError:
        return [], None
    except OSError as e:
        return [], f"could not read {path.name}: {type(e).__name__}"
    if os.name == "posix" and st.st_mode & 0o077:
        return [], f"{path.name} is readable by other users, so it was not loaded. Run: chmod 600 {path}"
    loaded = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        return [], f"could not read {path.name}: {type(e).__name__}"
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or not value or name in os.environ:
            continue
        os.environ[name] = value
        loaded.append(name)
    return loaded, None


def allowed_hosts() -> set[str]:
    """Host names this server answers to. A page on another site that rebinds its DNS to 127.0.0.1 still
    sends its own name in the Host header, so refusing unknown names shuts that attack out.
    Add more (a reverse proxy name, say) with SHADOWCRUMBS_ALLOWED_HOSTS=name1,name2."""
    extra = os.environ.get("SHADOWCRUMBS_ALLOWED_HOSTS", "")
    return {"127.0.0.1", "localhost", "::1"} | {h.strip().lower() for h in extra.split(",") if h.strip()}


def subdomain_wordlist() -> Path:
    """The guess list for subdomain_brute. Point SHADOWCRUMBS_SUBDOMAIN_WORDLIST at a bigger one if a job needs it."""
    raw = os.environ.get("SHADOWCRUMBS_SUBDOMAIN_WORDLIST", "").strip()
    return Path(raw).expanduser() if raw else ROOT / "source_packs" / "subdomains.txt"


# Mainframe ports first (telnet, TN3270, DB2, MQ, WebSphere), then the usual exposed services.
DEFAULT_PORTS = (21, 22, 23, 25, 80, 110, 143, 175, 443, 445, 446, 448, 992, 993, 995, 1414, 1433, 1521, 2809,
                 3270, 3306, 3389, 5432, 5900, 8080, 8443, 9080, 9443, 10007, 50000)


def scan_ports() -> list:
    """The TCP ports port_scan tries. SHADOWCRUMBS_PORTS (comma separated) replaces the default list, bad entries are dropped."""
    raw = os.environ.get("SHADOWCRUMBS_PORTS", "").strip()
    if not raw:
        return list(DEFAULT_PORTS)
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 65535 and int(part) not in ports:
            ports.append(int(part))
    return (ports or list(DEFAULT_PORTS))[:MAX_PORTS]
