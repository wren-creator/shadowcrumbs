#!/usr/bin/env bash
# Start Shadowcrumbs in the background. ./start.sh --help for switches.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/shadowcrumbs.pid"
PORT_FILE="$SCRIPT_DIR/shadowcrumbs.port"
LOG_FILE="$SCRIPT_DIR/shadowcrumbs.log"
PORT=8470
FOREGROUND=0

usage() {
    cat <<USAGE
Usage: ./start.sh [switches]

  --demo         run on the bundled fixture data, no network (Acme Demo Corp / acme-demo.test)
  --port N       listen on port N (default 8470)
  --delay SECS   seconds between live search queries (default 8)
  --foreground   run in this terminal instead of the background (Ctrl-C to stop)
  --status       say whether it is running and exit
  -h, --help     this text

Environment passed through if set: BRAVE_API_KEY, HIBP_API_KEY, DEHASHED_API_KEY, URLSCAN_API_KEY, GITHUB_TOKEN,
SHADOWCRUMBS_SEARXNG_URL, SHADOWCRUMBS_PERSONAL_PLUGINS, SHADOWCRUMBS_BREACH_FILE, SHADOWCRUMBS_BLOCK_MINUTES, SHADOWCRUMBS_IGNORE_BLOCK,
SHADOWCRUMBS_DATA, SHADOWCRUMBS_UA.
Binds to localhost only, on purpose. The data is client confidential.
USAGE
}

running_pid() {
    [ -f "$PID_FILE" ] || return 1
    local pid; pid=$(cat "$PID_FILE")
    kill -0 "$pid" 2>/dev/null && echo "$pid"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --demo)
            export SHADOWCRUMBS_SEARCH=fixture
            export SHADOWCRUMBS_FIXTURE="$SCRIPT_DIR/fixtures/demo.json" ;;
        --port)       PORT="${2:?--port needs a number}"; shift ;;
        --delay)      export SHADOWCRUMBS_SEARCH_DELAY="${2:?--delay needs seconds}"; shift ;;
        --foreground) FOREGROUND=1 ;;
        --status)
            if pid=$(running_pid); then echo "Shadowcrumbs is running (PID $pid) at http://127.0.0.1:$(cat "$PORT_FILE" 2>/dev/null || echo "$PORT")"
            else echo "Shadowcrumbs is not running."; fi
            exit 0 ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "Unknown switch: $1"; usage; exit 1 ;;
    esac
    shift
done

if pid=$(running_pid); then
    echo "Shadowcrumbs is already running (PID $pid). Use ./stop.sh first."
    exit 1
fi
rm -f "$PID_FILE"

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $PORT is already in use by something else. Try --port N."
    exit 1
fi

cd "$SCRIPT_DIR"
if [ ! -x .venv/bin/python ]; then
    echo "No .venv found. Setting one up..."
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi

[ -n "${SHADOWCRUMBS_SEARCH:-}" ] && echo "Demo mode: fixture data, no network."

if [ "$FOREGROUND" -eq 1 ]; then
    echo "Shadowcrumbs at http://127.0.0.1:$PORT (Ctrl-C to stop)"
    exec .venv/bin/python run.py --port "$PORT"
fi

nohup .venv/bin/python run.py --port "$PORT" >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "$PORT" > "$PORT_FILE"

# Give it a moment, then make sure it actually came up.
for _ in $(seq 1 20); do
    if curl -fs -o /dev/null "http://127.0.0.1:$PORT/"; then
        echo "Shadowcrumbs started (PID $(cat "$PID_FILE")) at http://127.0.0.1:$PORT"
        echo "Logs: $LOG_FILE"
        exit 0
    fi
    kill -0 "$(cat "$PID_FILE")" 2>/dev/null || break
    sleep 0.5
done
echo "Shadowcrumbs did not come up. Last log lines:"
tail -n 15 "$LOG_FILE"
rm -f "$PID_FILE"
exit 1
