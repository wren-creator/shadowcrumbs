#!/usr/bin/env bash
# Stop Shadowcrumbs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$SCRIPT_DIR/shadowcrumbs.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "No PID file, Shadowcrumbs is not running (or was started with --foreground)."
    exit 0
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping Shadowcrumbs (PID $PID)..."
    kill "$PID"
    for _ in $(seq 1 10); do
        kill -0 "$PID" 2>/dev/null || break
        sleep 0.5
    done
    if kill -0 "$PID" 2>/dev/null; then
        echo "Did not exit cleanly, sending SIGKILL."
        kill -9 "$PID"
    fi
    echo "Stopped."
else
    echo "Stale PID file (PID $PID is gone). Cleaning up."
fi
rm -f "$PID_FILE" "$SCRIPT_DIR/shadowcrumbs.port"
