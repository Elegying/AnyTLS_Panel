#!/bin/bash
# Local start script for AnyTLS Panel.
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q -r requirements.txt

PORT=${PORT:-8866}
echo ""
echo "  AnyTLS Panel"
echo "  URL: http://0.0.0.0:${PORT}"
echo "  User: admin"
echo "  On first start, the generated password is written next to anytls.db as .initial_admin_password."
echo ""

exec gunicorn -w 2 -b 0.0.0.0:${PORT} --timeout 60 app:app
