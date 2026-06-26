#!/usr/bin/env bash
# AnyTLS Panel one-command deployment.
# Usage: bash deploy.sh [port]
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
PORT="${1:-${ANYTLS_PANEL_PORT:-8866}}"
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
REPO_URL="${ANYTLS_REPO_URL:-https://github.com/Elegying/SSR_Panel.git}"
REPO_REF="${ANYTLS_REPO_REF:-main}"
REPO_SUBDIR="${ANYTLS_REPO_SUBDIR:-anytls-panel}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"

log() {
    printf '[anytls-panel] %s\n' "$*"
}

fail() {
    printf '[anytls-panel] ERROR: %s\n' "$*" >&2
    exit 1
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "please run as root"
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    fail "invalid port: $PORT"
fi

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
        apt-get update -qq
        apt-get install -y -qq "$@"
        return
    fi
    fail "apt-get not found; this installer currently supports Ubuntu/Debian"
}

ensure_runtime() {
    local missing=()
    command -v python3 >/dev/null 2>&1 || missing+=(python3)
    command -v git >/dev/null 2>&1 || missing+=(git)
    command -v curl >/dev/null 2>&1 || missing+=(curl)

    if (( ${#missing[@]} > 0 )); then
        log "installing missing tools: ${missing[*]}"
        install_packages "${missing[@]}"
    fi

    if ! python3 -m venv --help >/dev/null 2>&1 || ! python3 -m pip --version >/dev/null 2>&1; then
        log "installing Python venv/pip support"
        install_packages python3-venv python3-pip
    fi
}

sync_project_files() {
    mkdir -p "$PANEL_DIR"

    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/app.py" ]]; then
        log "copying local project files to $PANEL_DIR"
        find "$PANEL_DIR" -mindepth 1 -maxdepth 1 ! -name anytls.db -exec rm -rf {} +
        cp "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/requirements.txt" "$PANEL_DIR/"
        if [[ -f "$SCRIPT_DIR/uninstall.sh" ]]; then
            cp "$SCRIPT_DIR/uninstall.sh" "$PANEL_DIR/"
            chmod +x "$PANEL_DIR/uninstall.sh" 2>/dev/null || true
        fi
        mkdir -p "$PANEL_DIR/templates" "$PANEL_DIR/static"
        cp "$SCRIPT_DIR"/templates/*.html "$PANEL_DIR/templates/"
        if compgen -G "$SCRIPT_DIR/static/*" >/dev/null; then
            cp -R "$SCRIPT_DIR"/static/. "$PANEL_DIR/static/"
        fi
        return
    fi

    log "fetching project from $REPO_URL ($REPO_REF)"

    local tmp_dir
    local source_dir
    tmp_dir="$(mktemp -d /tmp/anytls-panel.XXXXXX)"
    git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$tmp_dir" -q
    source_dir="$tmp_dir"
    if [[ -n "$REPO_SUBDIR" ]]; then
        source_dir="$tmp_dir/$REPO_SUBDIR"
    fi
    if [[ ! -f "$source_dir/app.py" ]]; then
        rm -rf "$tmp_dir"
        fail "project files not found: $source_dir"
    fi
    find "$PANEL_DIR" -mindepth 1 -maxdepth 1 ! -name anytls.db -exec rm -rf {} +
    cp -R "$source_dir"/. "$PANEL_DIR"/
    rm -rf "$tmp_dir"
}

generate_password() {
    python3 - <<'PY'
import secrets
import string

alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(18)))
PY
}

prepare_admin_credentials() {
    ADMIN_USER="${ANYTLS_ADMIN_USER:-admin}"
    ADMIN_PASS="${ANYTLS_ADMIN_PASS:-}"
    FRESH_DB=0
    if [[ ! -f "$PANEL_DIR/anytls.db" ]]; then
        FRESH_DB=1
    fi
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS="$(generate_password)"
    fi
}

install_python_deps() {
    cd "$PANEL_DIR"
    if [[ ! -d venv ]]; then
        log "creating Python virtual environment"
        python3 -m venv venv
    fi

    log "installing Python dependencies"
    "$PANEL_DIR/venv/bin/python" -m pip install --upgrade pip -q
    "$PANEL_DIR/venv/bin/python" -m pip install -q -r requirements.txt
}

initialize_database() {
    if [[ "$FRESH_DB" -eq 1 ]]; then
        log "initializing admin account"
        ANYTLS_DATABASE="$PANEL_DIR/anytls.db" \
        ANYTLS_ADMIN_USER="$ADMIN_USER" \
        ANYTLS_ADMIN_PASS="$ADMIN_PASS" \
        "$PANEL_DIR/venv/bin/python" - <<'PY'
import app
app.init_db()
PY
    fi
}

write_service() {
    log "writing systemd service"
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=AnyTLS Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/gunicorn -w 2 -b 0.0.0.0:${PORT} --timeout 60 app:app
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    sleep 2
    systemctl is-active --quiet "$SERVICE_NAME" || {
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
        fail "service failed to start"
    }
}

print_summary() {
    local local_ip public_ip
    local_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    public_ip="$(curl -s -m 5 ifconfig.me 2>/dev/null || true)"

    echo
    log "deployment succeeded"
    [[ -n "$local_ip" ]] && echo "  Local URL:  http://${local_ip}:${PORT}"
    [[ -n "$public_ip" ]] && echo "  Public URL: http://${public_ip}:${PORT}"
    if [[ "$FRESH_DB" -eq 1 ]]; then
        echo "  Username:   ${ADMIN_USER}"
        echo "  Password:   ${ADMIN_PASS}"
    else
        echo "  Existing database preserved; use the current admin credentials."
    fi
    echo "  Service:    ${SERVICE_NAME}"
    echo
}

ensure_runtime
sync_project_files
prepare_admin_credentials
install_python_deps
initialize_database
write_service
start_service
print_summary
