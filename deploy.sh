#!/usr/bin/env bash
# AnyTLS Panel one-command deployment.
# Usage: bash deploy.sh [port]
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
PORT="${1:-${ANYTLS_PANEL_PORT:-8866}}"
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
REPO_URL="${ANYTLS_REPO_URL:-https://github.com/Elegying/AnyTLS_Panel.git}"
REPO_REF="${ANYTLS_REPO_REF:-main}"
REPO_SUBDIR="${ANYTLS_REPO_SUBDIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
APT_UPDATED=0
RPM_UPDATED=0

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
        if [[ "$APT_UPDATED" -eq 0 ]]; then
            apt-get update -qq
            APT_UPDATED=1
        fi
        apt-get install -y -qq --no-install-recommends "$@"
        return
    fi

    local rpm_cmd=""
    if command -v dnf >/dev/null 2>&1; then
        rpm_cmd="dnf"
    elif command -v yum >/dev/null 2>&1; then
        rpm_cmd="yum"
    fi
    if [[ -n "$rpm_cmd" ]]; then
        if [[ "$RPM_UPDATED" -eq 0 ]]; then
            "$rpm_cmd" makecache -q >/dev/null 2>&1 || true
            RPM_UPDATED=1
        fi
        "$rpm_cmd" install -y -q "$@"
        return
    fi

    fail "no supported package manager found; please use Ubuntu/Debian or CentOS/RHEL"
}

python_venv_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "python3-venv python3-pip"
    else
        echo "python3-pip python3-virtualenv"
    fi
}

ensure_runtime() {
    local missing=()
    local cmd_pkg cmd pkg
    for cmd_pkg in "python3:python3" "git:git" "curl:curl" "systemctl:systemd"; do
        cmd="${cmd_pkg%%:*}"
        pkg="${cmd_pkg##*:}"
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$pkg")
    done

    if (( ${#missing[@]} > 0 )); then
        log "installing missing tools: ${missing[*]}"
        install_packages "${missing[@]}"
    fi

    local probe_dir
    probe_dir="$(mktemp -d /tmp/anytls-venv-check.XXXXXX)"
    if ! python3 -m venv "$probe_dir/venv" >/dev/null 2>&1 || ! "$probe_dir/venv/bin/python" -m pip --version >/dev/null 2>&1; then
        rm -rf "$probe_dir"
        log "installing Python venv support"
        install_packages $(python_venv_packages) || install_packages python3-pip || true
        probe_dir="$(mktemp -d /tmp/anytls-venv-check.XXXXXX)"
        if ! python3 -m venv "$probe_dir/venv" >/dev/null 2>&1 || ! "$probe_dir/venv/bin/python" -m pip --version >/dev/null 2>&1; then
            rm -rf "$probe_dir"
            fail "Python venv/pip support is unavailable after installing system packages"
        fi
        rm -rf "$probe_dir"
    else
        rm -rf "$probe_dir"
    fi
}

sync_project_files() {
    mkdir -p "$PANEL_DIR"

    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/app.py" ]]; then
        log "copying local project files to $PANEL_DIR"
        find "$PANEL_DIR" -mindepth 1 -maxdepth 1 \
            ! -name anytls.db \
            ! -name .secret_key \
            ! -name .initial_admin_password \
            ! -name .traffic_api_token \
            ! -name venv \
            -exec rm -rf {} +
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
    find "$PANEL_DIR" -mindepth 1 -maxdepth 1 \
        ! -name anytls.db \
        ! -name .secret_key \
        ! -name .initial_admin_password \
        ! -name .traffic_api_token \
        ! -name venv \
        -exec rm -rf {} +
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

generate_api_token() {
    python3 - <<'PY'
import secrets

print(secrets.token_urlsafe(32))
PY
}

prepare_admin_credentials() {
    ADMIN_USER="${ANYTLS_ADMIN_USER:-admin}"
    ADMIN_PASS="${ANYTLS_ADMIN_PASS:-}"
    ADMIN_PASSWORD_FILE="${ANYTLS_ADMIN_PASSWORD_FILE:-$PANEL_DIR/.initial_admin_password}"
    GENERATED_ADMIN_PASS=0
    FRESH_DB=0
    if [[ ! -f "$PANEL_DIR/anytls.db" ]]; then
        FRESH_DB=1
    fi
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS="$(generate_password)"
        GENERATED_ADMIN_PASS=1
    fi
}

persist_generated_admin_password() {
    if [[ "$FRESH_DB" -eq 1 && "$GENERATED_ADMIN_PASS" -eq 1 ]]; then
        mkdir -p "$(dirname "$ADMIN_PASSWORD_FILE")"
        install -m 600 /dev/null "$ADMIN_PASSWORD_FILE"
        printf '%s\n' "$ADMIN_PASS" > "$ADMIN_PASSWORD_FILE"
        chmod 600 "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
    fi
}

prepare_traffic_api_token() {
    TRAFFIC_API_TOKEN_FILE="${ANYTLS_TRAFFIC_API_TOKEN_FILE:-$PANEL_DIR/.traffic_api_token}"
    TRAFFIC_API_TOKEN="${ANYTLS_TRAFFIC_API_TOKEN:-}"
    FRESH_TRAFFIC_API_TOKEN=0

    if [[ -z "$TRAFFIC_API_TOKEN" && -s "$TRAFFIC_API_TOKEN_FILE" ]]; then
        TRAFFIC_API_TOKEN="$(tr -d '\r\n' < "$TRAFFIC_API_TOKEN_FILE")"
    fi
    if [[ -z "$TRAFFIC_API_TOKEN" ]]; then
        TRAFFIC_API_TOKEN="$(generate_api_token)"
        FRESH_TRAFFIC_API_TOKEN=1
    fi

    mkdir -p "$(dirname "$TRAFFIC_API_TOKEN_FILE")"
    install -m 600 /dev/null "$TRAFFIC_API_TOKEN_FILE"
    printf '%s\n' "$TRAFFIC_API_TOKEN" > "$TRAFFIC_API_TOKEN_FILE"
    chmod 600 "$TRAFFIC_API_TOKEN_FILE" 2>/dev/null || true
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
Environment=ANYTLS_TRAFFIC_API_TOKEN_FILE=${TRAFFIC_API_TOKEN_FILE}

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
        if [[ "${ANYTLS_SHOW_SECRETS:-0}" = "1" ]]; then
            echo "  Password:   ${ADMIN_PASS}"
        elif [[ "$GENERATED_ADMIN_PASS" -eq 1 ]]; then
            echo "  Password file: ${ADMIN_PASSWORD_FILE}"
        else
            echo "  Password:   hidden (set ANYTLS_SHOW_SECRETS=1 to print)"
        fi
    else
        echo "  Existing database preserved; use the current admin credentials."
    fi
    echo "  Traffic API token file: ${TRAFFIC_API_TOKEN_FILE}"
    if [[ "${FRESH_TRAFFIC_API_TOKEN:-0}" -eq 1 && "${ANYTLS_SHOW_SECRETS:-0}" = "1" ]]; then
        echo "  Traffic API token: ${TRAFFIC_API_TOKEN}"
    fi
    echo "  Service:    ${SERVICE_NAME}"
    echo
}

ensure_runtime
sync_project_files
prepare_admin_credentials
persist_generated_admin_password
prepare_traffic_api_token
install_python_deps
initialize_database
write_service
start_service
print_summary
