#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="anytls-panel-ci"
SERVICE_USER="anytls-panel-ci"
PANEL_DIR="/srv/anytls-panel-ci-$$"
DATA_DIR="$PANEL_DIR/data"
BACKUP_ROOT="/var/backups/$SERVICE_NAME"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"

cleanup() {
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl stop caddy >/dev/null 2>&1 || true
    rm -f -- "$UNIT_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf -- "${PANEL_DIR:?}" "${BACKUP_ROOT:?}"
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_endpoint() {
    local url="$1"
    if curl --fail --silent --show-error --retry 10 --retry-delay 1 \
        --retry-connrefused "$url"; then
        return
    fi
    systemctl status "$SERVICE_NAME" --no-pager || true
    journalctl -u "$SERVICE_NAME" -n 100 --no-pager || true
    return 1
}

# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]
[[ "${EUID:-$(id -u)}" -eq 0 ]]

install -d -o root -g root -m 755 "$PANEL_DIR"
while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -n "$entry" && "$entry" != \#* ]] || continue
    destination="$PANEL_DIR/$entry"
    install -d -o root -g root -m 755 "${destination%/*}"
    cp -a -- "$REPO_ROOT/$entry" "$destination"
done < "$REPO_ROOT/release-files.txt"

python3 -m venv "$PANEL_DIR/venv"
"$PANEL_DIR/venv/bin/python" -m pip install --require-hashes \
    -r "$PANEL_DIR/requirements.txt" -q
useradd --system --user-group --home-dir "$PANEL_DIR" \
    --shell /usr/sbin/nologin "$SERVICE_USER"
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 "$DATA_DIR"

"$PANEL_DIR/venv/bin/python" - "$DATA_DIR/anytls.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    db.execute('''CREATE TABLE accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        subscribe_url TEXT NOT NULL,
        traffic_limit_gb REAL DEFAULT 250,
        traffic_used_bytes INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        notes TEXT DEFAULT '',
        node_count INTEGER DEFAULT 0,
        last_synced_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
PY
chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/anytls.db"
chmod 600 "$DATA_DIR/anytls.db"

(
    cd "$PANEL_DIR"
    runuser -u "$SERVICE_USER" -- env \
        ANYTLS_DATABASE="$DATA_DIR/anytls.db" \
        ANYTLS_SECRET_KEY_FILE="$DATA_DIR/.secret_key" \
        ANYTLS_TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token" \
        ANYTLS_ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password" \
        "$PANEL_DIR/venv/bin/python" -c 'import app'
)

"$PANEL_DIR/venv/bin/python" - "$DATA_DIR/anytls.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    assert db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 2
    columns = {row[1] for row in db.execute('PRAGMA table_info(accounts)')}
    assert {'sub_token', 'traffic_upload_bytes', 'traffic_download_bytes'} <= columns
PY

# Reuse the production unit renderer, then prove systemd can start and restart it.
# shellcheck source=../deploy.sh
source "$REPO_ROOT/deploy.sh"
trap cleanup EXIT
SERVICE_NAME="anytls-panel-ci"
SERVICE_USER="anytls-panel-ci"
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
PANEL_DIR="/srv/anytls-panel-ci-$$"
DATA_DIR="$PANEL_DIR/data"
SECRET_KEY_FILE="$DATA_DIR/.secret_key"
TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"
ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"
SYSTEMD_UNIT_DIR="/etc/systemd/system"
BIND_HOST="127.0.0.1"
PORT="18866"
SESSION_COOKIE_SECURE=0
TRUST_PROXY=0
ALLOW_PRIVATE_SUBSCRIPTIONS=0
BACKUP_ROOT="/var/backups/$SERVICE_NAME"
HEALTHCHECK_SCRIPT="/usr/local/sbin/${SERVICE_NAME}-healthcheck"
HEALTHCHECK_SERVICE="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.service"
HEALTHCHECK_TIMER="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.timer"
CADDY_RESTART_DROPIN="${SYSTEMD_UNIT_DIR}/caddy.service.d/${SERVICE_NAME}-restart.conf"

write_service
systemd-analyze verify "$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
wait_for_endpoint http://127.0.0.1:18866/readyz
systemctl restart "$SERVICE_NAME"
wait_for_endpoint http://127.0.0.1:18866/healthz
curl --fail --silent --dump-header - --output /dev/null \
    http://127.0.0.1:18866/login | grep -qi '^Content-Security-Policy:'

# Validate the supported Caddy source/minimum and a real reverse-proxy config.
ensure_runtime
capture_caddy_state
ensure_caddy
assert_supported_caddy_version
temp_caddy="$(mktemp)"
printf 'http://127.0.0.1:18080 { reverse_proxy 127.0.0.1:18866 }\n' > "$temp_caddy"
caddy validate --config "$temp_caddy" --adapter caddyfile
rm -f -- "$temp_caddy"

# Persist three snapshots, prove checksum validation, and prove rotation keeps two.
OLD_INSTALL_PRESENT=1
OLD_PANEL_UNIT_PRESENT=1
OLD_PANEL_ACTIVE=1
OLD_PANEL_ENABLED=1
OLD_PANEL_ENABLEMENT_MANAGED=1
OLD_CADDY_UNIT_PRESENT=1
OLD_CADDY_ACTIVE=0
OLD_CADDY_ENABLED=1
OLD_CADDY_ENABLEMENT_MANAGED=1
OLD_HEALTH_TIMER_UNIT_PRESENT=0
OLD_HEALTH_TIMER_ACTIVE=0
OLD_HEALTH_TIMER_ENABLED=0
OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=1
CODE_BACKED_UP=1
DATABASE_BACKED_UP=1
DATABASE_STATE_CAPTURED=1
CONFIG_BACKED_UP=1
for _index in 1 2 3; do
    ROLLBACK_DIR="$(mktemp -d)"
    install -d -m 700 "$ROLLBACK_DIR/code"
    cp -a -- "$PANEL_DIR/app.py" "$ROLLBACK_DIR/code/app.py"
    cp -a -- "$DATA_DIR/anytls.db" "$ROLLBACK_DIR/anytls.db"
    persist_rollback_backup
    rm -rf -- "${ROLLBACK_DIR:?}"
done
[[ "$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' | wc -l)" -eq 2 ]]
latest_backup="$(resolve_persistent_backup latest)"
verify_rollback_backup "$latest_backup"
printf '\n# tampered\n' >> "$latest_backup/code/app.py"
if (verify_rollback_backup "$latest_backup") >/dev/null 2>&1; then
    echo 'tampered rollback backup unexpectedly verified' >&2
    exit 1
fi
