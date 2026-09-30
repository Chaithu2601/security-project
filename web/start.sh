#!/usr/bin/env bash
# Start the DAST Harness web UI.
#   ./web/start.sh        -> http://127.0.0.1:8700
set -e
cd "$(dirname "$0")/.."
if [ ! -d .venv ]; then
  echo "Creating virtualenv (.venv) ..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi
echo "DAST Harness UI  ->  http://127.0.0.1:8700   (Ctrl-C to stop)"
exec ./.venv/bin/python web/app.py
