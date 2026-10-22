#!/usr/bin/env bash
# One front door for the whole stack: the dashboard and, if you want it, your own SearXNG.
#   ./shadowcrumbs.sh start [--searxng] [--demo] [--port N] [--delay SECS]
#   ./shadowcrumbs.sh status
#   ./shadowcrumbs.sh stop
#   ./shadowcrumbs.sh restart [same switches as start]
# It is a thin wrapper over start.sh, stop.sh and tools/searxng.sh, which still work on their own.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
SX_PORT="${SEARXNG_PORT:-8888}"
SX_URL="http://127.0.0.1:$SX_PORT"
SX_MARK="$DIR/shadowcrumbs.searxng"     # present only when this script started SearXNG, so stop knows it is ours
DATA="${SHADOWCRUMBS_DATA:-$DIR/data}"

usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; }

searxng_answers() {   # true when the JSON API gives a real reply, which is the check that matters
    curl -fs -m 5 "$1/search?q=example&format=json" 2>/dev/null | grep -q '"results"'
}

wait_for_searxng() {
    echo -n "Waiting for SearXNG"
    for _ in $(seq 1 40); do
        if searxng_answers "$SX_URL"; then echo " up."; return 0; fi
        echo -n "."; sleep 1
    done
    echo " no answer after 40 seconds."; return 1
}

app_state() {   # prints the status line, returns 0 when running
    ./start.sh --status
    ./start.sh --status | grep -q "is running"
}

cmd_start() {
    local want_sx=0 pass=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --searxng) want_sx=1 ;;
            --demo|--foreground) pass+=("$1") ;;
            --port|--delay) pass+=("$1" "${2:?$1 needs a value}"); shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "Unknown switch: $1"; usage; exit 1 ;;
        esac
        shift
    done

    if [ "$want_sx" -eq 1 ]; then
        if [ -n "${SHADOWCRUMBS_SEARXNG_URL:-}" ]; then
            echo "SHADOWCRUMBS_SEARXNG_URL is already set ($SHADOWCRUMBS_SEARXNG_URL), using that one."
        else
            command -v docker >/dev/null || { echo "Docker is not installed, so --searxng cannot work."; exit 1; }
            docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Start it and try again."; exit 1; }
            if searxng_answers "$SX_URL"; then
                echo "SearXNG already answering at $SX_URL."
            else
                ./tools/searxng.sh up
                touch "$SX_MARK"
                wait_for_searxng || { echo "Check ./tools/searxng.sh logs"; exit 1; }
            fi
            export SHADOWCRUMBS_SEARXNG_URL="$SX_URL"
        fi
    fi
    ./start.sh ${pass[@]+"${pass[@]}"}
}

cmd_stop() {
    ./stop.sh
    if [ -f "$SX_MARK" ]; then
        echo "Stopping SearXNG (this script started it)."
        ./tools/searxng.sh down
        rm -f "$SX_MARK"
    elif docker ps --filter name=shadowcrumbs-searxng -q 2>/dev/null | grep -q .; then
        echo "A SearXNG container is running that this script did not start. Left alone. ./tools/searxng.sh down to stop it."
    fi
}

cmd_status() {
    local rc=0
    app_state || rc=1
    if docker info >/dev/null 2>&1 && [ -n "$(docker ps --filter name=shadowcrumbs-searxng -q)" ]; then
        if searxng_answers "$SX_URL"; then echo "SearXNG: up and answering at $SX_URL"
        else echo "SearXNG: container running but the JSON API is not answering at $SX_URL"; fi
    else
        echo "SearXNG: not running"
    fi
    .venv/bin/python -I - "$DIR" <<'PY' 2>/dev/null || true
import sys
sys.path.insert(0, sys.argv[1])
import os
from shadowcrumbs import config
_, problem = config.load_env_file()
print("Keys: " + ", ".join(f"{k} {'set' if os.environ.get(k) else 'not set'}" for k in config.KEY_NAMES[:2]))
if problem:
    print("Keys: WARNING " + problem)
PY
    if [ -f "$DATA/search_blocked.json" ]; then
        .venv/bin/python -I - "$DATA/search_blocked.json" <<'PY' 2>/dev/null || echo "DuckDuckGo: a block marker exists"
import json, sys, time
at = json.load(open(sys.argv[1]))["at"]
print(f"DuckDuckGo: blocked {int((time.time() - at) / 60)} minutes ago, the app stays quiet for an hour")
PY
    else
        echo "DuckDuckGo: no block on record"
    fi
    return $rc
}

case "${1:-}" in
    start)   shift; cmd_start "$@" ;;
    stop)    cmd_stop ;;
    status)  cmd_status ;;
    restart) shift; cmd_stop; cmd_start "$@" ;;
    -h|--help|"") usage ;;
    *) echo "Unknown command: $1"; usage; exit 1 ;;
esac
