#!/usr/bin/env bash
# One front door for the whole stack: the dashboard and your own SearXNG, which it starts for you when it can.
#   ./shadowcrumbs.sh start [--no-searxng | --searxng] [--searxng-port N] [--demo] [--port N] [--delay SECS]
#                           --port is the dashboard, --searxng-port is SearXNG (default 8888)
#   ./shadowcrumbs.sh status
#   ./shadowcrumbs.sh stop
#   ./shadowcrumbs.sh restart [same switches as start]
# It is a thin wrapper over start.sh (dashboard only), stop.sh and tools/searxng.sh, which still work on their own.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
SX_PORT="${SEARXNG_PORT:-8888}"
SX_URL="http://127.0.0.1:$SX_PORT"
SX_MARK="$DIR/shadowcrumbs.searxng"     # present only when this script started SearXNG, so stop knows it is ours; holds its port
DATA="${SHADOWCRUMBS_DATA:-$DIR/data}"

set_sx_port() {   # one place that changes the port, so the URL, the check and the container all agree
    case "$1" in
        ''|*[!0-9]*) echo "--searxng-port needs a number between 1 and 65535, got: $1"; exit 1 ;;
    esac
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then echo "--searxng-port needs a number between 1 and 65535, got: $1"; exit 1; fi
    SX_PORT="$1"
    SX_URL="http://127.0.0.1:$SX_PORT"
    export SEARXNG_PORT="$SX_PORT"          # tools/searxng.sh and its compose file read this
}

adopt_marked_port() {   # status and stop follow the port this script started SearXNG on, unless SEARXNG_PORT says otherwise
    [ -z "${SEARXNG_PORT:-}" ] && [ -s "$SX_MARK" ] && set_sx_port "$(tr -d '[:space:]' < "$SX_MARK")"
    return 0
}

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }

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

ensure_searxng() {   # $1 = auto or required. Exports the URL on success. In auto mode any problem means carry on without it.
    local mode="$1"
    skip() {
        if [ "$mode" = required ]; then echo "$1"; exit 1; fi
        echo "$1 Carrying on without SearXNG (--no-searxng silences this)."
        return 1
    }
    if [ -n "${SHADOWCRUMBS_SEARXNG_URL:-}" ]; then
        echo "SHADOWCRUMBS_SEARXNG_URL is already set ($SHADOWCRUMBS_SEARXNG_URL), using that one."
        return 0
    fi
    if searxng_answers "$SX_URL"; then
        echo "SearXNG already answering at $SX_URL."
    else
        if lsof -nP -iTCP:"$SX_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
            skip "Port $SX_PORT is taken by something that is not SearXNG (use --searxng-port N to pick another)." || return 1
        fi
        command -v docker >/dev/null || { skip "Docker is not installed, so there is no SearXNG." || return 1; }
        docker info >/dev/null 2>&1 || { skip "Docker is installed but not running." || return 1; }
        echo "Starting SearXNG (the first run downloads its image, which can take a minute)."
        ./tools/searxng.sh up
        echo "$SX_PORT" > "$SX_MARK"
        wait_for_searxng || { skip "SearXNG did not answer. Check ./tools/searxng.sh logs." || return 1; }
    fi
    export SHADOWCRUMBS_SEARXNG_URL="$SX_URL"
}

cmd_start() {
    local sx=auto demo=0 pass=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --searxng) sx=required ;;       # insist on it: stop with an error if it cannot start
            --no-searxng) sx=off ;;
            --searxng-port) set_sx_port "${2:?--searxng-port needs a value}"; shift ;;
            --demo) demo=1; pass+=("$1") ;;
            --foreground) pass+=("$1") ;;
            --port|--delay) pass+=("$1" "${2:?$1 needs a value}"); shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "Unknown switch: $1"; usage; exit 1 ;;
        esac
        shift
    done

    # demo mode and a forced engine never touch the network, so there is nothing for SearXNG to do
    if [ "$sx" = auto ] && { [ "$demo" -eq 1 ] || [ -n "${SHADOWCRUMBS_SEARCH:-}" ]; }; then sx=off; fi
    if [ "$sx" != off ]; then
        ensure_searxng "$sx" || true
    fi
    ./start.sh ${pass[@]+"${pass[@]}"}
}

cmd_stop() {
    adopt_marked_port
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
    adopt_marked_port
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
