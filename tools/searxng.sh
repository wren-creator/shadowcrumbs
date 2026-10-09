#!/usr/bin/env bash
# Run your own SearXNG for Shadowcrumbs: ./tools/searxng.sh up | down | status | logs
# Then:  export SHADOWCRUMBS_SEARXNG_URL=http://127.0.0.1:8888   and start Shadowcrumbs.
set -euo pipefail
cd "$(dirname "$0")/searxng"
PORT="${SEARXNG_PORT:-8888}"
SECRET_FILE=".secret"     # random, made on first use, gitignored

case "${1:-}" in
  up)
    [ -f "$SECRET_FILE" ] || { umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SECRET_FILE"; }
    SEARXNG_SECRET="$(cat "$SECRET_FILE")" SEARXNG_PORT="$PORT" docker compose up -d
    echo "SearXNG is starting at http://127.0.0.1:$PORT (give it a few seconds)"
    echo "export SHADOWCRUMBS_SEARXNG_URL=http://127.0.0.1:$PORT"
    ;;
  down)   SEARXNG_SECRET=x docker compose down ;;
  status) docker ps --filter name=shadowcrumbs-searxng --format '{{.Names}}  {{.Status}}  {{.Ports}}' ;;
  logs)   SEARXNG_SECRET=x docker compose logs --tail 50 ;;
  *) echo "usage: $0 up | down | status | logs"; exit 1 ;;
esac
