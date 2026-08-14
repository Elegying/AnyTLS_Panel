#!/bin/bash
# Local start script for AnyTLS Panel.
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
# shellcheck source=/dev/null
source venv/bin/activate
pip install -q -r requirements.txt

PORT=${PORT:-8866}
HOST=${HOST:-127.0.0.1}
echo ""
echo "  AnyTLS Panel"
echo "  URL: http://${HOST}:${PORT}"
echo "  User: admin"
echo "  On first start, the generated password is written next to anytls.db as .initial_admin_password."
echo ""

exec gunicorn --workers 1 --threads 4 --no-control-socket --bind "${HOST}:${PORT}" --timeout 120 app:app
