#!/usr/bin/env bash
set -euo pipefail

PORT="${FROGY_WEB_PORT:-8787}"
HOST="${FROGY_WEB_HOST:-0.0.0.0}"

cat <<BANNER
[frogy] Docker container is up. Control plane will be served at http://${HOST}:${PORT}
[frogy] If you mapped the port (e.g. -p ${PORT}:${PORT}), open that URL from your browser.
[frogy] Press Ctrl+C to stop the container.
BANNER

if command -v mountpoint >/dev/null 2>&1; then
  if ! mountpoint -q /opt/frogy/output; then
    echo "[frogy] Tip: mount your host output directory (-v \"\$(pwd)/output:/opt/frogy/output\") to persist scans between containers."
  fi
fi

exec python -m frogy_web
