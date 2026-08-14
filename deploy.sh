#!/usr/bin/env bash
# AnyTLS Panel one-command deployment.
# Usage: bash deploy.sh [port]
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
PORT="${1:-${ANYTLS_PANEL_PORT:-8866}}"
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
SERVICE_USER="${ANYTLS_SERVICE_USER:-anytls-panel}"
BIND_HOST="${ANYTLS_BIND_HOST:-127.0.0.1}"
SESSION_COOKIE_SECURE="${ANYTLS_SESSION_COOKIE_SECURE:-1}"
TRUST_PROXY="${ANYTLS_TRUST_PROXY:-0}"
ALLOW_PRIVATE_SUBSCRIPTIONS="${ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS:-0}"
REPO_URL="${ANYTLS_REPO_URL:-https://github.com/Elegying/AnyTLS_Panel.git}"
REPO_REF="${ANYTLS_REPO_REF:-main}"
REPO_SUBDIR="${ANYTLS_REPO_SUBDIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
APT_UPDATED=0
RPM_UPDATED=0
DATA_DIR=""
SECRET_KEY_FILE=""
TRAFFIC_API_TOKEN_FILE=""
ADMIN_PASSWORD_FILE=""
SYSTEMD_UNIT_DIR="/etc/systemd/system"

log() {
    printf '[anytls-panel] %s\n' "$*"
}

fail() {
    printf '[anytls-panel] ERROR: %s\n' "$*" >&2
    exit 1
}

validate_panel_dir() {
    while [[ "$PANEL_DIR" != "/" && "$PANEL_DIR" == */ ]]; do
        PANEL_DIR="${PANEL_DIR%/}"
    done
    if ! [[ "$PANEL_DIR" =~ ^/(opt|srv)/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        fail "ANYTLS_PANEL_DIR must be a dedicated /opt/<name> or /srv/<name> directory"
    fi
    case "/$PANEL_DIR/" in
        */../*|*/./*)
            fail "ANYTLS_PANEL_DIR must not contain . or .. components"
            ;;
    esac

    local current=""
    local component
    local components=()
    IFS='/' read -r -a components <<< "${PANEL_DIR#/}"
    for component in "${components[@]}"; do
        current="${current}/${component}"
        if [[ -L "$current" ]]; then
            fail "ANYTLS_PANEL_DIR must not traverse symlinks: $current"
        fi
    done

    local parent_dir="${PANEL_DIR%/*}"
    if [[ -e "$parent_dir" ]]; then
        local metadata
        if ! metadata="$(stat -c '%u %a' "$parent_dir" 2>/dev/null)"; then
            metadata="$(stat -f '%u %Lp' "$parent_dir" 2>/dev/null)" || \
                fail "cannot inspect ANYTLS_PANEL_DIR parent permissions"
        fi
        local owner mode
        read -r owner mode <<< "$metadata"
        if [[ "$owner" != "0" ]] || (( (8#$mode & 8#022) != 0 )); then
            fail "ANYTLS_PANEL_DIR parent must be root-owned and not group/world writable"
        fi
    fi
}

validate_install_target() {
    if [[ ! -e "$PANEL_DIR" ]]; then
        return
    fi
    if [[ ! -d "$PANEL_DIR" ]]; then
        fail "ANYTLS_PANEL_DIR exists and is not a directory"
    fi

    local first_entry
    if ! first_entry="$(find "$PANEL_DIR" -mindepth 1 -maxdepth 1 -print -quit)"; then
        fail "cannot inspect ANYTLS_PANEL_DIR"
    fi
    if [[ -z "$first_entry" ]]; then
        return
    fi
    local marker="$PANEL_DIR/.anytls-panel-install"
    if [[ -f "$marker" && ! -L "$marker" ]] && \
       [[ "$(< "$marker")" == "anytls-panel-managed-v1" ]]; then
        local marker_metadata
        if ! marker_metadata="$(stat -c '%u %a' "$marker" 2>/dev/null)"; then
            marker_metadata="$(stat -f '%u %Lp' "$marker" 2>/dev/null)" || \
                fail "cannot inspect installation marker permissions"
        fi
        local marker_owner marker_mode
        read -r marker_owner marker_mode <<< "$marker_metadata"
        if [[ "$marker_owner" == "0" ]] && (( (8#$marker_mode & 8#022) == 0 )); then
            return
        fi
    fi
    if [[ -e "$marker" || -L "$marker" ]]; then
        fail "refusing an untrusted installation marker: $marker"
    fi

    local service_file="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
    if [[ -f "$PANEL_DIR/app.py" && -f "$PANEL_DIR/requirements.txt" && \
          -f "$PANEL_DIR/templates/base.html" && -f "$PANEL_DIR/anytls.db" && \
          -d "$PANEL_DIR/venv" && -f "$service_file" ]] && \
       grep -Fqx "WorkingDirectory=${PANEL_DIR}" "$service_file"; then
        log "adopting verified legacy AnyTLS Panel directory"
        return
    fi
    fail "refusing to clear a non-empty unmarked directory: $PANEL_DIR"
}

validate_service_target() {
    local service_file="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
    if [[ ! -e "$service_file" && ! -L "$service_file" ]]; then
        if command -v systemctl >/dev/null 2>&1; then
            local fragment_path
            fragment_path="$(systemctl show -p FragmentPath --value \
                "$SERVICE_NAME" 2>/dev/null || true)"
            if [[ -n "$fragment_path" && "$fragment_path" != "$service_file" ]]; then
                fail "service name belongs to another systemd unit: $fragment_path"
            fi
        fi
        return
    fi
    if [[ -L "$service_file" || ! -f "$service_file" ]]; then
        fail "refusing an unsafe systemd unit target: $service_file"
    fi
    if ! grep -Fqx "WorkingDirectory=${PANEL_DIR}" "$service_file" || \
       ! grep -Fq "ExecStart=${PANEL_DIR}/venv/bin/gunicorn " "$service_file"; then
        fail "systemd unit does not belong to this panel directory: $service_file"
    fi
}

validate_secret_file_path() {
    local path="$1"
    local default_path="$2"
    local variable_name="$3"
    if [[ -L "$path" ]] || [[ -e "$path" && ! -f "$path" ]]; then
        fail "$variable_name must be a regular non-symlink file"
    fi
    local parent_dir="${path%/*}"
    if [[ -L "$parent_dir" ]]; then
        fail "$variable_name parent must not be a symlink"
    fi
    if [[ "$path" != "$default_path" ]]; then
        if ! [[ "$path" =~ ^/etc/anytls-panel/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
            fail "$variable_name must use its default data path or /etc/anytls-panel/<name>"
        fi
        if [[ -e "$parent_dir" ]]; then
            local metadata
            if ! metadata="$(stat -c '%u %a' "$parent_dir" 2>/dev/null)"; then
                metadata="$(stat -f '%u %Lp' "$parent_dir" 2>/dev/null)" || \
                    fail "cannot inspect $variable_name parent permissions"
            fi
            local owner mode
            read -r owner mode <<< "$metadata"
            if [[ "$owner" != "0" ]] || (( (8#$mode & 8#022) != 0 )); then
                fail "$variable_name parent must be root-owned and not group/world writable"
            fi
        fi
    fi
}

validate_secret_paths() {
    DATA_DIR="$PANEL_DIR/data"
    SECRET_KEY_FILE="${ANYTLS_SECRET_KEY_FILE:-$DATA_DIR/.secret_key}"
    TRAFFIC_API_TOKEN_FILE="${ANYTLS_TRAFFIC_API_TOKEN_FILE:-$DATA_DIR/.traffic_api_token}"
    ADMIN_PASSWORD_FILE="${ANYTLS_ADMIN_PASSWORD_FILE:-$DATA_DIR/.initial_admin_password}"
    validate_secret_file_path "$SECRET_KEY_FILE" "$DATA_DIR/.secret_key" \
        "ANYTLS_SECRET_KEY_FILE"
    validate_secret_file_path "$TRAFFIC_API_TOKEN_FILE" "$DATA_DIR/.traffic_api_token" \
        "ANYTLS_TRAFFIC_API_TOKEN_FILE"
    validate_secret_file_path "$ADMIN_PASSWORD_FILE" "$DATA_DIR/.initial_admin_password" \
        "ANYTLS_ADMIN_PASSWORD_FILE"
}

validate_configuration() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        fail "please run as root"
    fi
    validate_panel_dir
    validate_secret_paths
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
        fail "invalid port: $PORT"
    fi
    if ! [[ "$SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]]; then
        fail "invalid service name: $SERVICE_NAME"
    fi
    if ! [[ "$SERVICE_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        fail "invalid service user: $SERVICE_USER"
    fi
    if [[ "$SERVICE_USER" == "root" ]]; then
        fail "service user must not be root"
    fi
    if ! [[ "$BIND_HOST" =~ ^[0-9a-fA-F:.]+$ ]]; then
        fail "invalid bind host: $BIND_HOST"
    fi
    for flag_value in "$SESSION_COOKIE_SECURE" "$TRUST_PROXY" "$ALLOW_PRIVATE_SUBSCRIPTIONS"; do
        if ! [[ "$flag_value" =~ ^[01]$ ]]; then
            fail "security flags must be 0 or 1"
        fi
    done
}

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

ensure_service_user() {
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        if ! command -v useradd >/dev/null 2>&1; then
            if command -v apt-get >/dev/null 2>&1; then
                install_packages passwd
            else
                install_packages shadow-utils
            fi
        fi
        local nologin_shell
        nologin_shell="$(command -v nologin || printf '/usr/sbin/nologin')"
        useradd --system --user-group --home-dir "$PANEL_DIR" \
            --shell "$nologin_shell" "$SERVICE_USER"
    fi
    if [[ "$(id -u "$SERVICE_USER")" -eq 0 ]] || \
       [[ "$(id -g "$SERVICE_USER")" -eq 0 ]]; then
        fail "service user must have a non-root uid and gid"
    fi
    SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
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
    for cmd_pkg in \
        "python3:python3" "git:git" "curl:curl" \
        "systemctl:systemd" "runuser:util-linux"; do
        cmd="${cmd_pkg%%:*}"
        pkg="${cmd_pkg##*:}"
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$pkg")
    done

    if (( ${#missing[@]} > 0 )); then
        log "installing missing tools: ${missing[*]}"
        install_packages "${missing[@]}"
    fi

    if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
        fail "Python 3.10 or newer is required"
    fi

    local probe_dir
    probe_dir="$(mktemp -d /tmp/anytls-venv-check.XXXXXX)"
    if ! python3 -m venv "$probe_dir/venv" >/dev/null 2>&1 || ! "$probe_dir/venv/bin/python" -m pip --version >/dev/null 2>&1; then
        rm -rf "$probe_dir"
        log "installing Python venv support"
        local venv_packages=()
        read -r -a venv_packages <<< "$(python_venv_packages)"
        install_packages "${venv_packages[@]}" || install_packages python3-pip || true
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

stop_service_for_update() {
    validate_service_target
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "stopping existing service before replacing code"
        systemctl stop "$SERVICE_NAME"
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            fail "existing service did not stop cleanly"
        fi
    fi
}

prepare_state_directory() {
    if [[ -L "$DATA_DIR" ]] || [[ -e "$DATA_DIR" && ! -d "$DATA_DIR" ]]; then
        fail "panel data path must be a real directory"
    fi
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 750 "$DATA_DIR"

    local database_file="$DATA_DIR/anytls.db"
    if [[ -L "$database_file" ]] || \
       [[ -e "$database_file" && ! -f "$database_file" ]]; then
        fail "panel database must be a regular non-symlink file"
    fi
    if [[ ! -e "$database_file" && -f "$PANEL_DIR/anytls.db" ]]; then
        if [[ -L "$PANEL_DIR/anytls.db" ]]; then
            fail "legacy panel database must not be a symlink"
        fi
        log "migrating database into the isolated data directory"
        runuser -u "$SERVICE_USER" -- python3 - \
            "$PANEL_DIR/anytls.db" "$database_file" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as target:
    source.backup(target)
    if target.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise SystemExit('migrated database quick_check failed')
PY
        chmod 600 "$database_file"
    fi

    local state_name source_file target_file
    for state_name in .secret_key .traffic_api_token .initial_admin_password; do
        source_file="$PANEL_DIR/$state_name"
        target_file="$DATA_DIR/$state_name"
        if [[ -L "$target_file" ]] || \
           [[ -e "$target_file" && ! -f "$target_file" ]]; then
            fail "panel state file must be a regular non-symlink file: $target_file"
        fi
        if [[ ! -e "$target_file" && -e "$source_file" ]]; then
            if [[ -L "$source_file" || ! -f "$source_file" ]]; then
                fail "legacy panel state file must be regular: $source_file"
            fi
            install -m 600 "$source_file" "$target_file"
        fi
    done
    local data_marker="$DATA_DIR/.anytls-panel-data"
    if [[ -L "$data_marker" ]] || [[ -e "$data_marker" && ! -f "$data_marker" ]]; then
        fail "panel data marker must be a regular non-symlink file"
    fi
    install -m 600 /dev/null "$data_marker"
    printf '%s\n' 'anytls-panel-data-v1' > "$data_marker"

    local install_marker="$PANEL_DIR/.anytls-panel-install"
    if [[ -L "$install_marker" ]] || \
       [[ -e "$install_marker" && ! -f "$install_marker" ]]; then
        fail "panel installation marker must be a regular non-symlink file"
    fi
    install -m 600 /dev/null "$install_marker"
    printf '%s\n' 'anytls-panel-managed-v1' > "$install_marker"
}

prepare_external_secret_directories() {
    local secret_file parent_dir
    for secret_file in "$SECRET_KEY_FILE" "$TRAFFIC_API_TOKEN_FILE" "$ADMIN_PASSWORD_FILE"; do
        parent_dir="${secret_file%/*}"
        if [[ "$parent_dir" != "$DATA_DIR" ]]; then
            install -d -o root -g "$SERVICE_GROUP" -m 750 "$parent_dir"
        fi
    done
    validate_secret_paths
}

sync_project_files() {
    # Revalidate immediately before any cleanup; the root-owned parent prevents
    # unprivileged replacement of the target directory between both checks.
    validate_panel_dir
    validate_install_target
    mkdir -p "$PANEL_DIR"

    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/app.py" ]]; then
        log "copying local project files to $PANEL_DIR"
        find "$PANEL_DIR" -mindepth 1 -maxdepth 1 \
            ! -name data \
            -exec rm -rf {} +
        cp "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/security_utils.py" \
            "$SCRIPT_DIR/traffic_token.py" \
            "$SCRIPT_DIR/requirements.txt" "$PANEL_DIR/"
        if [[ -f "$SCRIPT_DIR/uninstall.sh" ]]; then
            cp "$SCRIPT_DIR/uninstall.sh" "$PANEL_DIR/"
            chmod +x "$PANEL_DIR/uninstall.sh" 2>/dev/null || true
        fi
        mkdir -p "$PANEL_DIR/templates" "$PANEL_DIR/static"
        cp "$SCRIPT_DIR"/templates/*.html "$PANEL_DIR/templates/"
        if compgen -G "$SCRIPT_DIR/static/*" >/dev/null; then
            cp -R "$SCRIPT_DIR"/static/. "$PANEL_DIR/static/"
        fi
        printf '%s\n' 'anytls-panel-managed-v1' > "$PANEL_DIR/.anytls-panel-install"
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
        ! -name data \
        -exec rm -rf {} +
    cp -R "$source_dir"/. "$PANEL_DIR"/
    printf '%s\n' 'anytls-panel-managed-v1' > "$PANEL_DIR/.anytls-panel-install"
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

generate_secret_key() {
    python3 - <<'PY'
import secrets

print(secrets.token_hex(32))
PY
}

prepare_admin_credentials() {
    ADMIN_USER="${ANYTLS_ADMIN_USER:-admin}"
    ADMIN_PASS="${ANYTLS_ADMIN_PASS:-}"
    GENERATED_ADMIN_PASS=0
    FRESH_DB=0
    if [[ ! -f "$DATA_DIR/anytls.db" ]]; then
        FRESH_DB=1
    fi
    if [[ -z "$ADMIN_PASS" ]]; then
        ADMIN_PASS="$(generate_password)"
        GENERATED_ADMIN_PASS=1
    fi
}

persist_generated_admin_password() {
    if [[ "$FRESH_DB" -eq 1 ]]; then
        validate_secret_paths
        install -m 600 /dev/null "$ADMIN_PASSWORD_FILE"
        printf '%s\n' "$ADMIN_PASS" > "$ADMIN_PASSWORD_FILE"
        chmod 600 "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
    fi
}

prepare_secret_key() {
    validate_secret_paths
    if [[ ! -s "$SECRET_KEY_FILE" ]]; then
        local secret_key
        secret_key="$(generate_secret_key)"
        install -m 600 /dev/null "$SECRET_KEY_FILE"
        printf '%s\n' "$secret_key" > "$SECRET_KEY_FILE"
    fi
}

prepare_traffic_api_token() {
    validate_secret_paths
    TRAFFIC_API_TOKEN="${ANYTLS_TRAFFIC_API_TOKEN:-}"
    FRESH_TRAFFIC_API_TOKEN=0

    if [[ -z "$TRAFFIC_API_TOKEN" && -s "$TRAFFIC_API_TOKEN_FILE" ]]; then
        TRAFFIC_API_TOKEN="$(tr -d '\r\n' < "$TRAFFIC_API_TOKEN_FILE")"
    fi
    if [[ -z "$TRAFFIC_API_TOKEN" ]]; then
        TRAFFIC_API_TOKEN="$(generate_api_token)"
        FRESH_TRAFFIC_API_TOKEN=1
    fi

    install -m 600 /dev/null "$TRAFFIC_API_TOKEN_FILE"
    printf '%s\n' "$TRAFFIC_API_TOKEN" > "$TRAFFIC_API_TOKEN_FILE"
    chmod 600 "$TRAFFIC_API_TOKEN_FILE" 2>/dev/null || true
}

install_python_deps() {
    cd "$PANEL_DIR"
    if [[ -e venv || -L venv ]]; then
        fail "refusing to reuse a pre-existing virtual environment"
    fi
    log "creating a fresh root-owned Python virtual environment"
    python3 -m venv venv

    log "installing Python dependencies"
    "$PANEL_DIR/venv/bin/python" -m pip install --upgrade pip -q
    "$PANEL_DIR/venv/bin/python" -m pip install -q -r requirements.txt
}

prepare_runtime_permissions() {
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    if [[ -f "$DATA_DIR/anytls.db" ]]; then
        chmod 600 "$DATA_DIR/anytls.db"
    fi
    for secret_file in "$SECRET_KEY_FILE" "$TRAFFIC_API_TOKEN_FILE" "$ADMIN_PASSWORD_FILE"; do
        if [[ -f "$secret_file" ]]; then
            chown "root:$SERVICE_GROUP" "$secret_file"
            chmod 640 "$secret_file"
        fi
    done
}

initialize_database() {
    log "initializing and migrating the database"
    runuser -u "$SERVICE_USER" -- env \
        ANYTLS_DATABASE="$DATA_DIR/anytls.db" \
        ANYTLS_SECRET_KEY_FILE="$SECRET_KEY_FILE" \
        ANYTLS_TRAFFIC_API_TOKEN_FILE="$TRAFFIC_API_TOKEN_FILE" \
        ANYTLS_ADMIN_PASSWORD_FILE="$ADMIN_PASSWORD_FILE" \
        ANYTLS_ADMIN_USER="$ADMIN_USER" \
        "$PANEL_DIR/venv/bin/python" - <<'PY'
import app
app.init_db()
PY
}

secure_panel_permissions() {
    chown -R "root:$SERVICE_GROUP" "$PANEL_DIR"
    chmod -R g-w,o-w "$PANEL_DIR"
    chmod 750 "$PANEL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
    if [[ -f "$DATA_DIR/anytls.db" ]]; then
        chmod 600 "$DATA_DIR/anytls.db"
    fi
    if [[ -f "$SECRET_KEY_FILE" ]]; then
        chown "root:$SERVICE_GROUP" "$SECRET_KEY_FILE"
        chmod 640 "$SECRET_KEY_FILE"
    fi
    if [[ -f "$TRAFFIC_API_TOKEN_FILE" ]]; then
        chown "root:$SERVICE_GROUP" "$TRAFFIC_API_TOKEN_FILE"
        chmod 640 "$TRAFFIC_API_TOKEN_FILE"
    fi
    if [[ -f "$ADMIN_PASSWORD_FILE" ]]; then
        chown root:root "$ADMIN_PASSWORD_FILE"
        chmod 600 "$ADMIN_PASSWORD_FILE"
    fi
    if [[ -f "$PANEL_DIR/.anytls-panel-install" ]]; then
        chown root:root "$PANEL_DIR/.anytls-panel-install"
        chmod 600 "$PANEL_DIR/.anytls-panel-install"
    fi
}

write_service() {
    validate_service_target
    log "writing systemd service"
    cat > "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=AnyTLS Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/gunicorn --workers 1 --threads 4 --no-control-socket --bind ${BIND_HOST}:${PORT} --timeout 120 app:app
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=${DATA_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=ANYTLS_DATABASE=${DATA_DIR}/anytls.db
Environment=ANYTLS_SECRET_KEY_FILE=${SECRET_KEY_FILE}
Environment=ANYTLS_TRAFFIC_API_TOKEN_FILE=${TRAFFIC_API_TOKEN_FILE}
Environment=ANYTLS_SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE}
Environment=ANYTLS_TRUST_PROXY=${TRUST_PROXY}
Environment=ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=${ALLOW_PRIVATE_SUBSCRIPTIONS}

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
    if [[ "$BIND_HOST" == "127.0.0.1" || "$BIND_HOST" == "::1" ]]; then
        echo "  Local URL:  http://${BIND_HOST}:${PORT}"
        echo "  Panel is bound to loopback; publish it only through an HTTPS reverse proxy."
    else
        [[ -n "$local_ip" ]] && echo "  Local URL:  http://${local_ip}:${PORT}"
        [[ -n "$public_ip" ]] && echo "  Public URL: http://${public_ip}:${PORT}"
    fi
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

main() {
    validate_configuration
    validate_install_target
    validate_service_target
    ensure_runtime
    ensure_service_user
    stop_service_for_update
    prepare_state_directory
    sync_project_files
    prepare_external_secret_directories
    prepare_admin_credentials
    persist_generated_admin_password
    prepare_traffic_api_token
    prepare_secret_key
    install_python_deps
    prepare_runtime_permissions
    initialize_database
    secure_panel_permissions
    write_service
    start_service
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
