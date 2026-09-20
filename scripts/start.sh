#!/usr/bin/env bash
# Start the AIRCAP console. Loopback only.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -x ./.venv/bin/python ] || { echo "run 'make venv' first"; exit 1; }
echo "AIRCAP console -> http://127.0.0.1:8099   (ctrl-c to stop)"
exec ./.venv/bin/python -m uvicorn console.app:app --host 127.0.0.1 --port 8099 --log-level warning
