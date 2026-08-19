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
TRUST_PROXY="${ANYTLS_TRUST_PROXY:-1}"
ALLOW_PRIVATE_SUBSCRIPTIONS="${ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS:-0}"
PANEL_DOMAIN="${ANYTLS_PANEL_DOMAIN:-}"
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
CADDY_CONFIG_DIR="/etc/caddy"
CADDY_SITES_DIR="$CADDY_CONFIG_DIR/anytls-panel.d"
CADDYFILE="$CADDY_CONFIG_DIR/Caddyfile"
CADDY_INSTALLED_NOW=0
CADDYFILE_PREEXISTED=0
[[ -e "$CADDYFILE" || -L "$CADDYFILE" ]] && CADDYFILE_PREEXISTED=1
STAGE_DIR=""
RELEASE_SOURCE=""
WHEELHOUSE=""
ROLLBACK_DIR=""
CUTOVER_STARTED=0
ROLLBACK_FINISHED=0
DEPLOY_SUCCEEDED=0
OLD_PANEL_ACTIVE=0
OLD_CADDY_ACTIVE=0
OLD_HEALTH_TIMER_ACTIVE=0
OLD_INSTALL_PRESENT=0
CODE_BACKED_UP=0
DATABASE_BACKED_UP=0
DATABASE_STATE_CAPTURED=0
CONFIG_BACKED_UP=0
HEALTHCHECK_SCRIPT=""
HEALTHCHECK_SERVICE=""
HEALTHCHECK_TIMER=""
CADDY_RESTART_DROPIN=""

log() {
    printf '[anytls-panel] %s\n' "$*"
}

fail() {
    printf '[anytls-panel] ERROR: %s\n' "$*" >&2
    if [[ "${CUTOVER_STARTED:-0}" -eq 1 && "${ROLLBACK_FINISHED:-0}" -eq 0 ]] && \
       declare -F rollback_deployment >/dev/null 2>&1; then
        rollback_deployment || true
    fi
    exit 1
}

cleanup_deploy_artifacts() {
    if [[ -n "${STAGE_DIR:-}" && -d "$STAGE_DIR" ]]; then
        rm -rf -- "$STAGE_DIR"
    fi
    if [[ "${DEPLOY_SUCCEEDED:-0}" -eq 1 && -n "${ROLLBACK_DIR:-}" && \
          -d "$ROLLBACK_DIR" ]]; then
        rm -rf -- "$ROLLBACK_DIR"
    fi
}

handle_deploy_error() {
    local status="$1"
    trap - ERR
    if [[ "${CUTOVER_STARTED:-0}" -eq 1 && "${ROLLBACK_FINISHED:-0}" -eq 0 ]]; then
        rollback_deployment || true
    fi
    exit "$status"
}

trap 'handle_deploy_error $?' ERR
trap cleanup_deploy_artifacts EXIT

require_interactive_terminal() {
    if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
        fail "$1 must be set for non-interactive deployment"
    fi
}

validate_admin_user() {
    if ! [[ "$ADMIN_USER" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]]; then
        fail "administrator username must be 1-64 characters: letters, numbers, . _ @ -"
    fi
}

validate_admin_password() {
    if (( ${#ADMIN_PASS} < 8 || ${#ADMIN_PASS} > 128 )); then
        fail "administrator password must be 8-128 characters"
    fi
    if [[ "$ADMIN_PASS" == *$'\n'* || "$ADMIN_PASS" == *$'\r'* ]]; then
        fail "administrator password must not contain line breaks"
    fi
}

validate_panel_domain() {
    PANEL_DOMAIN="${PANEL_DOMAIN%.}"
    PANEL_DOMAIN="${PANEL_DOMAIN,,}"
    if (( ${#PANEL_DOMAIN} < 4 || ${#PANEL_DOMAIN} > 253 )) || \
       [[ "$PANEL_DOMAIN" != *.* ]] || \
       [[ "$PANEL_DOMAIN" =~ ^[0-9.]+$ ]]; then
        fail "panel domain must be a public DNS name such as panel.example.com"
    fi

    local label
    local labels=()
    IFS='.' read -r -a labels <<< "$PANEL_DOMAIN"
    for label in "${labels[@]}"; do
        if (( ${#label} < 1 || ${#label} > 63 )) || \
           ! [[ "$label" =~ ^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$ ]]; then
            fail "invalid panel domain: $PANEL_DOMAIN"
        fi
    done
}

prepare_panel_domain() {
    if [[ -z "$PANEL_DOMAIN" ]]; then
        require_interactive_terminal "ANYTLS_PANEL_DOMAIN"
        read -r -p "Panel domain (for example panel.example.com): " PANEL_DOMAIN </dev/tty
    fi
    validate_panel_domain
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
    if [[ "$BIND_HOST" != "127.0.0.1" && "$BIND_HOST" != "::1" ]]; then
        fail "automatic HTTPS requires ANYTLS_BIND_HOST to remain on loopback"
    fi
    if [[ "$SESSION_COOKIE_SECURE" != "1" || "$TRUST_PROXY" != "1" ]]; then
        fail "automatic HTTPS requires secure cookies and trusted proxy handling"
    fi
    HEALTHCHECK_SCRIPT="/usr/local/sbin/${SERVICE_NAME}-healthcheck"
    HEALTHCHECK_SERVICE="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.service"
    HEALTHCHECK_TIMER="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.timer"
    CADDY_RESTART_DROPIN="${SYSTEMD_UNIT_DIR}/caddy.service.d/${SERVICE_NAME}-restart.conf"
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
        "systemctl:systemd" "runuser:util-linux" "flock:util-linux"; do
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

ensure_caddy() {
    if command -v caddy >/dev/null 2>&1; then
        systemctl cat caddy.service >/dev/null 2>&1 || \
            fail "the caddy command exists but caddy.service is not installed"
        return
    fi

    log "installing Caddy for automatic Let's Encrypt HTTPS"
    if ! install_packages caddy; then
        fail "Caddy is unavailable from the configured package repositories"
    fi
    command -v caddy >/dev/null 2>&1 || fail "Caddy installation did not provide the caddy command"
    systemctl cat caddy.service >/dev/null 2>&1 || fail "Caddy installation did not provide caddy.service"
    CADDY_INSTALLED_NOW=1
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

backup_optional_file() {
    local source_path="$1"
    local backup_name="$2"
    if [[ -e "$source_path" || -L "$source_path" ]]; then
        cp -a -- "$source_path" "$ROLLBACK_DIR/$backup_name"
    else
        : > "$ROLLBACK_DIR/$backup_name.absent"
    fi
}

restore_optional_file() {
    local target_path="$1"
    local backup_name="$2"
    if [[ -f "$ROLLBACK_DIR/$backup_name.absent" ]]; then
        rm -f -- "$target_path"
    elif [[ -e "$ROLLBACK_DIR/$backup_name" || -L "$ROLLBACK_DIR/$backup_name" ]]; then
        install -d -m 755 "${target_path%/*}"
        cp -a -- "$ROLLBACK_DIR/$backup_name" "$target_path"
    fi
}

backup_configuration_for_rollback() {
    local site_file="$CADDY_SITES_DIR/${SERVICE_NAME}.caddy"
    backup_optional_file "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" panel.service
    backup_optional_file "$CADDYFILE" Caddyfile
    backup_optional_file "$site_file" caddy-site
    backup_optional_file "$HEALTHCHECK_SCRIPT" healthcheck-script
    backup_optional_file "$HEALTHCHECK_SERVICE" healthcheck.service
    backup_optional_file "$HEALTHCHECK_TIMER" healthcheck.timer
    backup_optional_file "$CADDY_RESTART_DROPIN" caddy-restart.conf
    backup_optional_file "$SECRET_KEY_FILE" secret-key
    backup_optional_file "$TRAFFIC_API_TOKEN_FILE" traffic-api-token
    backup_optional_file "$ADMIN_PASSWORD_FILE" admin-password
    backup_optional_file "$DATA_DIR/.anytls-panel-data" data-marker
    CONFIG_BACKED_UP=1
}

backup_database_for_rollback() {
    local database_file="$DATA_DIR/anytls.db"
    if [[ ! -f "$database_file" ]]; then
        DATABASE_STATE_CAPTURED=1
        return
    fi
    python3 - "$database_file" "$ROLLBACK_DIR/anytls.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1], timeout=30) as source, \
     sqlite3.connect(sys.argv[2], timeout=30) as target:
    source.backup(target)
    if target.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise SystemExit('rollback database quick_check failed')
PY
    chmod 600 "$ROLLBACK_DIR/anytls.db"
    DATABASE_BACKED_UP=1
    DATABASE_STATE_CAPTURED=1
}

backup_current_release() {
    install -d -m 700 "$ROLLBACK_DIR/code"
    # Mark the backup active before moving anything so a mid-loop failure
    # restores even a partially moved release.
    CODE_BACKED_UP=1
    if [[ -d "$PANEL_DIR" ]]; then
        while IFS= read -r -d '' entry; do
            mv -- "$entry" "$ROLLBACK_DIR/code/"
        done < <(find "$PANEL_DIR" -mindepth 1 -maxdepth 1 ! -name data -print0)
    fi
}

begin_cutover() {
    ROLLBACK_DIR="$(mktemp -d "${PANEL_DIR%/*}/.${SERVICE_NAME}-rollback.XXXXXX")"
    chmod 700 "$ROLLBACK_DIR"
    if [[ -f "$PANEL_DIR/.anytls-panel-install" && ! -L "$PANEL_DIR/.anytls-panel-install" ]] && \
       [[ "$(< "$PANEL_DIR/.anytls-panel-install")" == "anytls-panel-managed-v1" ]]; then
        OLD_INSTALL_PRESENT=1
    fi
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        OLD_PANEL_ACTIVE=1
    fi
    if systemctl is-active --quiet caddy; then
        OLD_CADDY_ACTIVE=1
    fi
    if systemctl is-active --quiet "${SERVICE_NAME}-healthcheck.timer"; then
        OLD_HEALTH_TIMER_ACTIVE=1
    fi
    backup_configuration_for_rollback
    CUTOVER_STARTED=1

    systemctl stop "${SERVICE_NAME}-healthcheck.timer" >/dev/null 2>&1 || true
    systemctl stop "${SERVICE_NAME}-healthcheck.service" >/dev/null 2>&1 || true
    stop_service_for_update
    prepare_state_directory
    backup_database_for_rollback
    backup_current_release
}

rollback_deployment() {
    [[ "${ROLLBACK_FINISHED:-0}" -eq 0 ]] || return 0
    ROLLBACK_FINISHED=1
    printf '[anytls-panel] deployment failed; restoring the previous release\n' >&2

    systemctl stop "${SERVICE_NAME}-healthcheck.timer" >/dev/null 2>&1 || true
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

    if [[ "$CODE_BACKED_UP" -eq 1 && -d "$PANEL_DIR" ]]; then
        find "$PANEL_DIR" -mindepth 1 -maxdepth 1 ! -name data \
            -exec rm -rf -- {} +
        if [[ -d "$ROLLBACK_DIR/code" ]]; then
            while IFS= read -r -d '' entry; do
                mv -- "$entry" "$PANEL_DIR/"
            done < <(find "$ROLLBACK_DIR/code" -mindepth 1 -maxdepth 1 -print0)
        fi
    fi
    if [[ "$OLD_INSTALL_PRESENT" -eq 0 ]]; then
        rm -f -- "$PANEL_DIR/.anytls-panel-install"
    fi

    if [[ "$DATABASE_STATE_CAPTURED" -eq 1 ]]; then
        rm -f -- "$DATA_DIR/anytls.db" "$DATA_DIR/anytls.db-wal" "$DATA_DIR/anytls.db-shm"
        if [[ "$DATABASE_BACKED_UP" -eq 1 ]]; then
            cp -a -- "$ROLLBACK_DIR/anytls.db" "$DATA_DIR/anytls.db"
            chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/anytls.db" || true
            chmod 600 "$DATA_DIR/anytls.db" || true
        fi
    fi

    if [[ "$CONFIG_BACKED_UP" -eq 1 ]]; then
        restore_optional_file "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" panel.service
        restore_optional_file "$CADDYFILE" Caddyfile
        restore_optional_file "$CADDY_SITES_DIR/${SERVICE_NAME}.caddy" caddy-site
        restore_optional_file "$HEALTHCHECK_SCRIPT" healthcheck-script
        restore_optional_file "$HEALTHCHECK_SERVICE" healthcheck.service
        restore_optional_file "$HEALTHCHECK_TIMER" healthcheck.timer
        restore_optional_file "$CADDY_RESTART_DROPIN" caddy-restart.conf
        restore_optional_file "$SECRET_KEY_FILE" secret-key
        restore_optional_file "$TRAFFIC_API_TOKEN_FILE" traffic-api-token
        restore_optional_file "$ADMIN_PASSWORD_FILE" admin-password
        restore_optional_file "$DATA_DIR/.anytls-panel-data" data-marker
    fi

    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ "$OLD_PANEL_ACTIVE" -eq 1 ]]; then
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if [[ "$OLD_CADDY_ACTIVE" -eq 1 ]]; then
        systemctl reload-or-restart caddy >/dev/null 2>&1 || true
    fi
    if [[ "$OLD_HEALTH_TIMER_ACTIVE" -eq 1 ]]; then
        systemctl enable --now "${SERVICE_NAME}-healthcheck.timer" >/dev/null 2>&1 || true
    fi
    CUTOVER_STARTED=0
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

prepare_release_source() {
    validate_panel_dir
    validate_install_target
    STAGE_DIR="$(mktemp -d "${PANEL_DIR%/*}/.${SERVICE_NAME}-stage.XXXXXX")"
    chmod 700 "$STAGE_DIR"
    RELEASE_SOURCE="$STAGE_DIR/source"
    install -d -m 755 "$RELEASE_SOURCE"

    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/app.py" ]]; then
        log "staging local project files before touching the active release"
        find "$SCRIPT_DIR" -mindepth 1 -maxdepth 1 \
            ! -name .git ! -name .venv ! -name venv ! -name data \
            ! -name .anytls-panel-install ! -name .anytls-panel-data \
            -exec cp -a -t "$RELEASE_SOURCE" -- {} +
    else
        log "fetching project from $REPO_URL ($REPO_REF) before stopping the service"
        local clone_dir="$STAGE_DIR/clone"
        git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$clone_dir" -q
        local source_dir="$clone_dir"
        if [[ -n "$REPO_SUBDIR" ]]; then
            source_dir="$clone_dir/$REPO_SUBDIR"
        fi
        [[ -d "$source_dir" ]] || fail "project source directory not found: $source_dir"
        find "$source_dir" -mindepth 1 -maxdepth 1 \
            ! -name .git ! -name .venv ! -name venv ! -name data \
            ! -name .anytls-panel-install ! -name .anytls-panel-data \
            -exec cp -a -t "$RELEASE_SOURCE" -- {} +
    fi

    for required_file in app.py security_utils.py traffic_token.py requirements.txt; do
        [[ -f "$RELEASE_SOURCE/$required_file" ]] || \
            fail "staged project is missing $required_file"
    done
    [[ -f "$RELEASE_SOURCE/templates/base.html" ]] || \
        fail "staged project templates are incomplete"
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
    ADMIN_USER="${ANYTLS_ADMIN_USER:-}"
    ADMIN_PASS="${ANYTLS_ADMIN_PASS:-}"
    FRESH_DB=0
    if [[ ! -f "$DATA_DIR/anytls.db" && ! -f "$PANEL_DIR/anytls.db" ]]; then
        FRESH_DB=1
    fi

    if [[ "$FRESH_DB" -ne 1 ]]; then
        return
    fi

    if [[ -z "$ADMIN_USER" ]]; then
        require_interactive_terminal "ANYTLS_ADMIN_USER"
        read -r -p "Panel administrator username: " ADMIN_USER </dev/tty
    fi
    validate_admin_user

    if [[ -z "$ADMIN_PASS" ]]; then
        require_interactive_terminal "ANYTLS_ADMIN_PASS"
        local password_confirmation=""
        read -r -s -p "Panel administrator password (8-128 characters): " ADMIN_PASS </dev/tty
        printf '\n' >/dev/tty
        read -r -s -p "Confirm panel administrator password: " password_confirmation </dev/tty
        printf '\n' >/dev/tty
        if [[ "$ADMIN_PASS" != "$password_confirmation" ]]; then
            fail "administrator passwords do not match"
        fi
    fi
    validate_admin_password
}

persist_admin_password() {
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

prepare_python_artifacts() {
    local build_venv="$STAGE_DIR/build-venv"
    WHEELHOUSE="$STAGE_DIR/wheelhouse"
    install -d -m 755 "$WHEELHOUSE"

    log "resolving and validating Python dependencies before stopping the service"
    python3 -m venv "$build_venv"
    "$build_venv/bin/python" -m pip install --upgrade pip -q
    "$build_venv/bin/python" -m pip download \
        --require-hashes --dest "$WHEELHOUSE" \
        -r "$RELEASE_SOURCE/requirements.txt" -q
    "$build_venv/bin/python" -m pip install \
        --require-hashes --no-index --find-links "$WHEELHOUSE" \
        -r "$RELEASE_SOURCE/requirements.txt" -q

    local smoke_dir="$STAGE_DIR/smoke"
    install -d -m 700 "$smoke_dir"
    (
        cd "$RELEASE_SOURCE"
        env \
            ANYTLS_DATABASE="$smoke_dir/anytls.db" \
            ANYTLS_SECRET_KEY_FILE="$smoke_dir/.secret_key" \
            ANYTLS_TRAFFIC_API_TOKEN_FILE="$smoke_dir/.traffic_api_token" \
            ANYTLS_ADMIN_PASSWORD_FILE="$smoke_dir/.initial_admin_password" \
            ANYTLS_ADMIN_USER="smoke-admin" \
            ANYTLS_ADMIN_PASS="smoke-password" \
            "$build_venv/bin/python" - <<'PY'
import app
app.init_db()
assert app.get_initial_admin_credentials()[0] == 'smoke-admin'
PY
    )
}

install_staged_release() {
    validate_panel_dir
    mkdir -p "$PANEL_DIR"
    find "$RELEASE_SOURCE" -mindepth 1 -maxdepth 1 \
        -exec cp -a -t "$PANEL_DIR" -- {} +
    install -o root -g root -m 600 /dev/null "$PANEL_DIR/.anytls-panel-install"
    printf '%s\n' 'anytls-panel-managed-v1' > "$PANEL_DIR/.anytls-panel-install"

    [[ ! -e "$PANEL_DIR/venv" && ! -L "$PANEL_DIR/venv" ]] || \
        fail "new release target unexpectedly contains a virtual environment"
    log "installing the pre-fetched dependency set without network access"
    python3 -m venv "$PANEL_DIR/venv"
    "$PANEL_DIR/venv/bin/python" -m pip install \
        --require-hashes --no-index --find-links "$WHEELHOUSE" \
        -r "$PANEL_DIR/requirements.txt" -q
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
    (
        cd "$PANEL_DIR"
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
    )
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

write_keepalive_config() {
    log "installing service recovery and end-to-end health checks"
    local script_tmp service_tmp timer_tmp caddy_tmp
    script_tmp="$(mktemp /tmp/anytls-healthcheck.XXXXXX)"
    service_tmp="$(mktemp /tmp/anytls-healthcheck-service.XXXXXX)"
    timer_tmp="$(mktemp /tmp/anytls-healthcheck-timer.XXXXXX)"
    caddy_tmp="$(mktemp /tmp/anytls-caddy-restart.XXXXXX)"

    cat > "$script_tmp" <<EOF
#!/usr/bin/env bash
set -u

exec 9>/run/lock/${SERVICE_NAME}-healthcheck.lock
flock -n 9 || exit 0

probe_backend() {
    curl --fail --silent --show-error --output /dev/null \\
        --connect-timeout 3 --max-time 8 \\
        http://127.0.0.1:${PORT}/login
}

probe_https() {
    curl --fail --silent --show-error --output /dev/null \\
        --connect-timeout 3 --max-time 8 \\
        --resolve ${PANEL_DOMAIN}:443:127.0.0.1 \\
        https://${PANEL_DOMAIN}/login
}

if ! systemctl is-active --quiet ${SERVICE_NAME} || ! probe_backend; then
    logger -p daemon.warning -t ${SERVICE_NAME}-healthcheck \\
        'panel health probe failed; restarting ${SERVICE_NAME}'
    systemctl restart ${SERVICE_NAME}
    sleep 3
    probe_backend || exit 1
fi

if ! systemctl is-active --quiet caddy || ! probe_https; then
    logger -p daemon.warning -t ${SERVICE_NAME}-healthcheck \\
        'HTTPS health probe failed; recovering Caddy'
    systemctl reload-or-restart caddy
    sleep 3
    probe_https || exit 1
fi
EOF

    cat > "$service_tmp" <<EOF
[Unit]
Description=AnyTLS Panel local health check and recovery (${SERVICE_NAME})
After=network-online.target ${SERVICE_NAME}.service caddy.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${HEALTHCHECK_SCRIPT}
TimeoutStartSec=30s
EOF

    cat > "$timer_tmp" <<EOF
[Unit]
Description=Run the AnyTLS Panel health check every minute (${SERVICE_NAME})

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s
RandomizedDelaySec=10s
Persistent=true
Unit=${SERVICE_NAME}-healthcheck.service

[Install]
WantedBy=timers.target
EOF

    cat > "$caddy_tmp" <<'EOF'
[Unit]
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Restart=on-failure
RestartSec=5s
EOF

    install -o root -g root -m 755 "$script_tmp" "$HEALTHCHECK_SCRIPT"
    install -o root -g root -m 644 "$service_tmp" "$HEALTHCHECK_SERVICE"
    install -o root -g root -m 644 "$timer_tmp" "$HEALTHCHECK_TIMER"
    install -d -o root -g root -m 755 "${CADDY_RESTART_DROPIN%/*}"
    install -o root -g root -m 644 "$caddy_tmp" "$CADDY_RESTART_DROPIN"
    rm -f -- "$script_tmp" "$service_tmp" "$timer_tmp" "$caddy_tmp"
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

verify_domain_resolution() {
    local resolved_addresses
    if ! resolved_addresses="$(python3 - "$PANEL_DOMAIN" <<'PY'
import socket
import sys

addresses = sorted({item[4][0] for item in socket.getaddrinfo(sys.argv[1], 443)})
print(', '.join(addresses))
PY
)" || [[ -z "$resolved_addresses" ]]; then
        fail "panel domain does not currently resolve: $PANEL_DOMAIN"
    fi
    log "domain resolves to: $resolved_addresses"
}

render_caddy_site() {
    cat <<EOF
${PANEL_DOMAIN} {
    tls {
        ca https://acme-v02.api.letsencrypt.org/directory
    }
    reverse_proxy 127.0.0.1:${PORT}
}
EOF
}

caddyfile_contains_only_panel_site() {
    [[ -f "$CADDYFILE" ]] || return 1
    local compact
    compact="$(sed '/^[[:space:]]*#/d' "$CADDYFILE" | tr -d '[:space:]')"
    [[ "$compact" == "${PANEL_DOMAIN}{reverse_proxy127.0.0.1:${PORT}}" || \
       "$compact" == "${PANEL_DOMAIN}{tls{cahttps://acme-v02.api.letsencrypt.org/directory}reverse_proxy127.0.0.1:${PORT}}" ]]
}

write_caddy_config() {
    local site_file="$CADDY_SITES_DIR/${SERVICE_NAME}.caddy"
    local import_line='import anytls-panel.d/*.caddy'
    local backup_dir
    local main_existed=0
    local site_existed=0

    if [[ -L "$CADDY_CONFIG_DIR" || -L "$CADDYFILE" || -L "$CADDY_SITES_DIR" || \
          -L "$site_file" ]]; then
        fail "refusing symlinked Caddy configuration paths"
    fi
    install -d -o root -g root -m 755 "$CADDY_CONFIG_DIR" "$CADDY_SITES_DIR"

    backup_dir="$(mktemp -d "$CADDY_CONFIG_DIR/.anytls-backup.XXXXXX")"
    chmod 700 "$backup_dir"
    if [[ -f "$CADDYFILE" ]]; then
        cp -a "$CADDYFILE" "$backup_dir/Caddyfile"
        main_existed=1
    fi
    if [[ -f "$site_file" ]]; then
        cp -a "$site_file" "$backup_dir/site.caddy"
        site_existed=1
    fi

    local temp_site
    temp_site="$(mktemp "$CADDY_CONFIG_DIR/.anytls-site.XXXXXX")"
    render_caddy_site > "$temp_site"
    install -o root -g root -m 644 "$temp_site" "$site_file"
    rm -f "$temp_site"

    if [[ "$CADDY_INSTALLED_NOW" -eq 1 && "$CADDYFILE_PREEXISTED" -eq 0 ]] || \
       [[ ! -s "$CADDYFILE" ]] || \
       caddyfile_contains_only_panel_site; then
        printf '%s\n' "$import_line" > "$CADDYFILE"
        chmod 644 "$CADDYFILE"
    elif ! grep -Fqx "$import_line" "$CADDYFILE"; then
        printf '\n%s\n' "$import_line" >> "$CADDYFILE"
    fi

    if ! caddy fmt --overwrite "$site_file" >/dev/null || \
       ! caddy validate --config "$CADDYFILE" >/dev/null; then
        if [[ "$main_existed" -eq 1 ]]; then
            cp -a "$backup_dir/Caddyfile" "$CADDYFILE"
        else
            rm -f "$CADDYFILE"
        fi
        if [[ "$site_existed" -eq 1 ]]; then
            cp -a "$backup_dir/site.caddy" "$site_file"
        else
            rm -f "$site_file"
        fi
        rm -f "$backup_dir/Caddyfile" "$backup_dir/site.caddy"
        rmdir "$backup_dir"
        fail "Caddy configuration validation failed; previous configuration restored"
    fi

    rm -f "$backup_dir/Caddyfile" "$backup_dir/site.caddy"
    rmdir "$backup_dir"
}

start_https_proxy() {
    systemctl enable caddy >/dev/null
    local caddy_action="start"
    if systemctl is-active --quiet caddy; then
        caddy_action="reload"
    fi
    if ! systemctl "$caddy_action" caddy; then
        journalctl -u caddy -n 80 --no-pager || true
        fail "Caddy failed to start; ensure public TCP ports 80 and 443 are available"
    fi

    local _
    for _ in {1..45}; do
        if curl --resolve "${PANEL_DOMAIN}:443:127.0.0.1" \
            --fail --silent --show-error --output /dev/null --max-time 5 \
            "https://${PANEL_DOMAIN}/login"; then
            return
        fi
        sleep 2
    done

    journalctl -u caddy -n 80 --no-pager || true
    fail "Let's Encrypt certificate verification timed out; check DNS and public ports 80/443"
}

start_keepalive() {
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}-healthcheck.timer" >/dev/null
    systemctl start "${SERVICE_NAME}-healthcheck.service"
    systemctl is-active --quiet "${SERVICE_NAME}-healthcheck.timer" || \
        fail "health-check timer failed to start"
}

print_summary() {
    echo
    log "deployment succeeded"
    echo "  Panel URL:  https://${PANEL_DOMAIN}"
    echo "  HTTPS:      Let's Encrypt certificate managed and renewed by Caddy"
    if [[ "$FRESH_DB" -eq 1 ]]; then
        echo "  Username:   ${ADMIN_USER}"
        if [[ "${ANYTLS_SHOW_SECRETS:-0}" = "1" ]]; then
            echo "  Password:   ${ADMIN_PASS}"
        else
            echo "  Password:   hidden"
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
    prepare_panel_domain
    prepare_admin_credentials
    ensure_runtime
    verify_domain_resolution
    ensure_caddy
    ensure_service_user
    prepare_release_source
    prepare_python_artifacts
    begin_cutover
    install_staged_release
    prepare_external_secret_directories
    persist_admin_password
    prepare_traffic_api_token
    prepare_secret_key
    prepare_runtime_permissions
    initialize_database
    secure_panel_permissions
    write_service
    write_keepalive_config
    start_service
    write_caddy_config
    start_https_proxy
    start_keepalive
    DEPLOY_SUCCEEDED=1
    CUTOVER_STARTED=0
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
