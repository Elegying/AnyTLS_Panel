#!/usr/bin/env bash
# AnyTLS Panel one-command deployment.
# Usage: bash deploy.sh [port] | bash deploy.sh --rollback [latest|backup-id]
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
PORT="${ANYTLS_PANEL_PORT:-8866}"
if [[ -n "${1:-}" && "${1:-}" != --* ]]; then
    PORT="$1"
fi
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
SERVICE_USER="${ANYTLS_SERVICE_USER:-anytls-panel}"
BIND_HOST="${ANYTLS_BIND_HOST:-127.0.0.1}"
SESSION_COOKIE_SECURE="${ANYTLS_SESSION_COOKIE_SECURE:-1}"
TRUST_PROXY="${ANYTLS_TRUST_PROXY:-1}"
ALLOW_PRIVATE_SUBSCRIPTIONS="${ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS:-0}"
ALLOW_HTTP_SUBSCRIPTIONS="${ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS:-0}"
ALLOW_PRIVATE_NODE_PROBES="${ANYTLS_ALLOW_PRIVATE_NODE_PROBES:-0}"
TRAFFIC_LOG_RETENTION_DAYS="${ANYTLS_TRAFFIC_LOG_RETENTION_DAYS:-90}"
MAX_REQUEST_BYTES="${ANYTLS_MAX_REQUEST_BYTES:-4194304}"
PANEL_DOMAIN="${ANYTLS_PANEL_DOMAIN:-}"
REPO_URL="${ANYTLS_REPO_URL:-https://github.com/Elegying/AnyTLS_Panel.git}"
REPO_REF="${ANYTLS_REPO_REF:-v1.2.2}"
REPO_SUBDIR="${ANYTLS_REPO_SUBDIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
APT_UPDATED=0
OS_RELEASE_FILE="/etc/os-release"
DATA_DIR=""
SECRET_KEY_FILE=""
TRAFFIC_API_TOKEN_FILE=""
ADMIN_PASSWORD_FILE=""
SYSTEMD_UNIT_DIR="/etc/systemd/system"
CADDY_CONFIG_DIR="/etc/caddy"
CADDY_SITES_DIR="$CADDY_CONFIG_DIR/anytls-panel.d"
CADDYFILE="$CADDY_CONFIG_DIR/Caddyfile"
CADDY_MIN_VERSION="2.11.4"
CADDY_KEY_FINGERPRINT="65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
BACKUP_ROOT="/var/backups/${SERVICE_NAME}"
MAX_PERSISTENT_BACKUPS=2
CADDY_INSTALLED_NOW=0
CADDY_INSTALL_ATTEMPTED=0
CADDY_STATE_CAPTURED=0
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
OLD_PANEL_ENABLED=0
OLD_PANEL_ENABLEMENT_MANAGED=0
OLD_PANEL_UNIT_PRESENT=0
OLD_CADDY_ACTIVE=0
OLD_CADDY_ENABLED=0
OLD_CADDY_ENABLEMENT_MANAGED=0
OLD_CADDY_UNIT_PRESENT=0
OLD_HEALTH_TIMER_ACTIVE=0
OLD_HEALTH_TIMER_ENABLED=0
OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=0
OLD_HEALTH_TIMER_UNIT_PRESENT=0
OLD_DATA_DATABASE_PRESENT=0
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
    if [[ "${DEPLOY_SUCCEEDED:-0}" -eq 0 && "${CUTOVER_STARTED:-0}" -eq 0 && \
          "${ROLLBACK_FINISHED:-0}" -eq 0 && \
          "${CADDY_INSTALL_ATTEMPTED:-0}" -eq 1 ]]; then
        local caddy_probe_status
        if systemd_unit_exists caddy; then
            systemctl stop caddy >/dev/null 2>&1 || \
                printf '[anytls-panel] ERROR: failed to stop Caddy after deployment failure\n' >&2
            if [[ "${OLD_CADDY_ENABLED:-0}" -eq 1 ]]; then
                systemctl enable caddy >/dev/null 2>&1 || \
                    printf '[anytls-panel] ERROR: failed to re-enable Caddy\n' >&2
            else
                systemctl disable caddy >/dev/null 2>&1 || \
                    printf '[anytls-panel] ERROR: failed to disable newly installed Caddy\n' >&2
            fi
            if [[ "${OLD_CADDY_ACTIVE:-0}" -eq 1 ]]; then
                systemctl start caddy >/dev/null 2>&1 || \
                    printf '[anytls-panel] ERROR: failed to restart Caddy\n' >&2
            fi
        else
            caddy_probe_status=$?
            if [[ "$caddy_probe_status" -eq 2 ]]; then
                printf '[anytls-panel] ERROR: failed to inspect Caddy after deployment failure; manual recovery required\n' >&2
            fi
        fi
    fi
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
    PANEL_DOMAIN="$(printf '%s' "$PANEL_DOMAIN" | tr '[:upper:]' '[:lower:]')"
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
    for flag_value in "$SESSION_COOKIE_SECURE" "$TRUST_PROXY" \
        "$ALLOW_PRIVATE_SUBSCRIPTIONS" "$ALLOW_HTTP_SUBSCRIPTIONS" \
        "$ALLOW_PRIVATE_NODE_PROBES"; do
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
    if ! [[ "$TRAFFIC_LOG_RETENTION_DAYS" =~ ^[0-9]+$ ]] || \
       (( TRAFFIC_LOG_RETENTION_DAYS < 1 || TRAFFIC_LOG_RETENTION_DAYS > 3650 )); then
        fail "ANYTLS_TRAFFIC_LOG_RETENTION_DAYS must be between 1 and 3650"
    fi
    if ! [[ "$MAX_REQUEST_BYTES" =~ ^[0-9]+$ ]] || \
       (( MAX_REQUEST_BYTES < 65536 || MAX_REQUEST_BYTES > 16777216 )); then
        fail "ANYTLS_MAX_REQUEST_BYTES must be between 65536 and 16777216"
    fi
    HEALTHCHECK_SCRIPT="/usr/local/sbin/${SERVICE_NAME}-healthcheck"
    HEALTHCHECK_SERVICE="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.service"
    HEALTHCHECK_TIMER="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.timer"
    CADDY_RESTART_DROPIN="${SYSTEMD_UNIT_DIR}/caddy.service.d/${SERVICE_NAME}-restart.conf"
}

validate_supported_os() {
    [[ -r "$OS_RELEASE_FILE" ]] || fail "Ubuntu 24.04 is required"
    local os_id version_id
    os_id="$(sed -n 's/^ID=//p' "$OS_RELEASE_FILE" | head -n 1 | tr -d '\"')"
    version_id="$(sed -n 's/^VERSION_ID=//p' "$OS_RELEASE_FILE" | head -n 1 | tr -d '\"')"
    if [[ "$os_id" != "ubuntu" || "$version_id" != "24.04" ]]; then
        fail "Ubuntu 24.04 is the only currently verified deployment target"
    fi
}

install_packages() {
    command -v apt-get >/dev/null 2>&1 || fail "Ubuntu 24.04 apt-get is required"
    export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
    if [[ "$APT_UPDATED" -eq 0 ]]; then
        apt-get update -qq
        APT_UPDATED=1
    fi
    apt-get install -y -qq --no-install-recommends "$@"
}

ensure_service_user() {
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        if ! command -v useradd >/dev/null 2>&1; then
            install_packages passwd
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
    echo "python3-venv python3-pip"
}

ensure_runtime() {
    local missing=()
    local cmd_pkg cmd pkg
    for cmd_pkg in \
        "python3:python3" "git:git" "curl:curl" "openssl:openssl" \
        "sha256sum:coreutils" \
        "systemctl:systemd" "runuser:util-linux" "flock:util-linux"; do
        cmd="${cmd_pkg%%:*}"
        pkg="${cmd_pkg##*:}"
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$pkg")
    done

    if (( ${#missing[@]} > 0 )); then
        log "installing missing tools: ${missing[*]}"
        install_packages "${missing[@]}"
    fi

    if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
        fail "Python 3.12 or newer is required"
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

systemd_unit_exists() {
    local load_state
    if ! load_state="$(systemctl show "$1" --property=LoadState --value 2>/dev/null)" || \
       [[ -z "$load_state" ]]; then
        return 2
    fi
    [[ "$load_state" != "not-found" ]]
}

capture_systemd_unit_state() {
    local unit="$1"
    local load_state active_state unit_file_state
    if ! load_state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)" || \
       [[ -z "$load_state" ]]; then
        fail "cannot inspect systemd load state for $unit"
    fi
    if [[ "$load_state" == "not-found" ]]; then
        printf '0 0 0 1\n'
        return
    fi
    if ! active_state="$(systemctl show "$unit" --property=ActiveState --value 2>/dev/null)" || \
       [[ -z "$active_state" ]]; then
        fail "cannot inspect systemd active state for $unit"
    fi
    if ! unit_file_state="$(systemctl show "$unit" --property=UnitFileState --value 2>/dev/null)"; then
        fail "cannot inspect systemd enablement for $unit"
    fi

    local was_active=0
    case "$active_state" in
        active|reloading) was_active=1 ;;
        inactive|failed) ;;
        *) fail "systemd unit is in a transitional state: $unit ($active_state)" ;;
    esac

    local was_enabled=0
    local enablement_managed=0
    case "$unit_file_state" in
        enabled|enabled-runtime)
            was_enabled=1
            enablement_managed=1
            ;;
        disabled)
            enablement_managed=1
            ;;
    esac
    printf '1 %s %s %s\n' \
        "$was_active" "$was_enabled" "$enablement_managed"
}

capture_caddy_state() {
    [[ "$CADDY_STATE_CAPTURED" -eq 0 ]] || return 0
    local snapshot
    snapshot="$(capture_systemd_unit_state caddy)"
    read -r OLD_CADDY_UNIT_PRESENT OLD_CADDY_ACTIVE \
        OLD_CADDY_ENABLED OLD_CADDY_ENABLEMENT_MANAGED <<< "$snapshot"
    CADDY_STATE_CAPTURED=1
}

installed_caddy_version() {
    caddy version 2>/dev/null | sed -nE 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/p'
}

caddy_version_is_supported() {
    local installed_version
    installed_version="$(installed_caddy_version)"
    [[ -n "$installed_version" ]] && \
        dpkg --compare-versions "$installed_version" ge "$CADDY_MIN_VERSION"
}

assert_supported_caddy_version() {
    caddy_version_is_supported || \
        fail "installed Caddy is older than the verified minimum ${CADDY_MIN_VERSION} after installing from the official repository"
}

install_caddy_from_official_repository() {
    install_packages debian-keyring debian-archive-keyring apt-transport-https curl gnupg

    local key_file source_file fingerprint
    key_file="$(mktemp /tmp/caddy-signing-key.XXXXXX)"
    source_file="$(mktemp /tmp/caddy-stable-source.XXXXXX)"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        --output "$key_file"
    fingerprint="$(gpg --show-keys --with-colons "$key_file" 2>/dev/null | \
        awk -F: '$1 == "fpr" {print $10; exit}')"
    [[ "$fingerprint" == "$CADDY_KEY_FINGERPRINT" ]] || \
        fail "Caddy repository signing-key fingerprint did not match"

    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        --output "$source_file"
    grep -Fqx \
        'deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main' \
        "$source_file" || fail "Caddy repository definition was unexpected"

    gpg --batch --yes --dearmor \
        --output /usr/share/keyrings/caddy-stable-archive-keyring.gpg "$key_file"
    install -o root -g root -m 644 "$source_file" \
        /etc/apt/sources.list.d/caddy-stable.list
    rm -f -- "$key_file" "$source_file"
    apt-get update -qq
    APT_UPDATED=1
    install_packages caddy
}

ensure_caddy() {
    local caddy_preexisting=0
    if command -v caddy >/dev/null 2>&1; then
        caddy_preexisting=1
        systemctl cat caddy.service >/dev/null 2>&1 || \
            fail "the caddy command exists but caddy.service is not installed"
        if caddy_version_is_supported; then
            return
        fi
        log "upgrading Caddy from the verified official repository"
    else
        log "installing Caddy for automatic public ACME HTTPS"
    fi

    CADDY_INSTALL_ATTEMPTED=1
    if ! install_caddy_from_official_repository; then
        fail "Caddy is unavailable from the configured package repositories"
    fi
    if [[ "$caddy_preexisting" -eq 0 ]]; then
        CADDY_INSTALLED_NOW=1
    fi
    command -v caddy >/dev/null 2>&1 || fail "Caddy installation did not provide the caddy command"
    systemctl cat caddy.service >/dev/null 2>&1 || fail "Caddy installation did not provide caddy.service"
    assert_supported_caddy_version
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
    if [[ "$OLD_DATA_DATABASE_PRESENT" -eq 0 ]]; then
        DATABASE_STATE_CAPTURED=1
        return
    fi
    [[ -f "$database_file" && ! -L "$database_file" ]] || \
        fail "existing data database disappeared before rollback backup"
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
    local snapshot
    snapshot="$(capture_systemd_unit_state "$SERVICE_NAME")"
    read -r OLD_PANEL_UNIT_PRESENT OLD_PANEL_ACTIVE \
        OLD_PANEL_ENABLED OLD_PANEL_ENABLEMENT_MANAGED <<< "$snapshot"
    capture_caddy_state
    snapshot="$(capture_systemd_unit_state "${SERVICE_NAME}-healthcheck.timer")"
    read -r OLD_HEALTH_TIMER_UNIT_PRESENT OLD_HEALTH_TIMER_ACTIVE \
        OLD_HEALTH_TIMER_ENABLED OLD_HEALTH_TIMER_ENABLEMENT_MANAGED \
        <<< "$snapshot"
    if [[ -f "$DATA_DIR/anytls.db" && ! -L "$DATA_DIR/anytls.db" ]]; then
        OLD_DATA_DATABASE_PRESENT=1
    fi
    backup_configuration_for_rollback
    CUTOVER_STARTED=1

    systemctl stop "${SERVICE_NAME}-healthcheck.timer" >/dev/null 2>&1 || true
    systemctl stop "${SERVICE_NAME}-healthcheck.service" >/dev/null 2>&1 || true
    stop_service_for_update
    backup_database_for_rollback
    prepare_state_directory
    backup_current_release
}

write_rollback_metadata() {
    local backup_dir="$1"
    local metadata="$backup_dir/rollback.meta"
    umask 077
    {
        printf 'format=anytls-panel-rollback-v1\n'
        printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'repo_ref=%s\n' "$REPO_REF"
        printf 'OLD_PANEL_UNIT_PRESENT=%s\n' "$OLD_PANEL_UNIT_PRESENT"
        printf 'OLD_PANEL_ACTIVE=%s\n' "$OLD_PANEL_ACTIVE"
        printf 'OLD_PANEL_ENABLED=%s\n' "$OLD_PANEL_ENABLED"
        printf 'OLD_PANEL_ENABLEMENT_MANAGED=%s\n' "$OLD_PANEL_ENABLEMENT_MANAGED"
        printf 'OLD_CADDY_UNIT_PRESENT=%s\n' "$OLD_CADDY_UNIT_PRESENT"
        printf 'OLD_CADDY_ACTIVE=%s\n' "$OLD_CADDY_ACTIVE"
        printf 'OLD_CADDY_ENABLED=%s\n' "$OLD_CADDY_ENABLED"
        printf 'OLD_CADDY_ENABLEMENT_MANAGED=%s\n' "$OLD_CADDY_ENABLEMENT_MANAGED"
        printf 'OLD_HEALTH_TIMER_UNIT_PRESENT=%s\n' "$OLD_HEALTH_TIMER_UNIT_PRESENT"
        printf 'OLD_HEALTH_TIMER_ACTIVE=%s\n' "$OLD_HEALTH_TIMER_ACTIVE"
        printf 'OLD_HEALTH_TIMER_ENABLED=%s\n' "$OLD_HEALTH_TIMER_ENABLED"
        printf 'OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=%s\n' \
            "$OLD_HEALTH_TIMER_ENABLEMENT_MANAGED"
        printf 'OLD_INSTALL_PRESENT=%s\n' "$OLD_INSTALL_PRESENT"
        printf 'CODE_BACKED_UP=%s\n' "$CODE_BACKED_UP"
        printf 'DATABASE_BACKED_UP=%s\n' "$DATABASE_BACKED_UP"
        printf 'DATABASE_STATE_CAPTURED=%s\n' "$DATABASE_STATE_CAPTURED"
        printf 'CONFIG_BACKED_UP=%s\n' "$CONFIG_BACKED_UP"
    } > "$metadata"

    (
        cd "$backup_dir"
        : > SHA256SUMS
        while IFS= read -r -d '' backup_file; do
            sha256sum "$backup_file" >> SHA256SUMS
        done < <(find . -type f ! -name SHA256SUMS -print0 | sort -z)
    )
    chmod 600 "$metadata" "$backup_dir/SHA256SUMS"
}

rotate_persistent_backups() {
    local backups=()
    local remove_count index
    mapfile -t backups < <(
        find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d \
            -name 'backup-*' -printf '%f\n' | sort
    )
    remove_count=$((${#backups[@]} - MAX_PERSISTENT_BACKUPS))
    if (( remove_count <= 0 )); then
        return
    fi
    for ((index = 0; index < remove_count; index++)); do
        rm -rf -- "${BACKUP_ROOT:?}/${backups[$index]}"
    done
}

persist_rollback_backup() {
    if [[ "$OLD_INSTALL_PRESENT" -ne 1 || ! -d "$ROLLBACK_DIR/code" ]]; then
        return
    fi
    install -d -o root -g root -m 700 "$BACKUP_ROOT"
    local backup_id target suffix=0
    backup_id="backup-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    target="$BACKUP_ROOT/$backup_id"
    while [[ -e "$target" ]]; do
        suffix=$((suffix + 1))
        backup_id="backup-$(date -u +%Y%m%dT%H%M%SZ)-$$-$suffix"
        target="$BACKUP_ROOT/$backup_id"
    done
    install -d -o root -g root -m 700 "$target"
    cp -a -- "$ROLLBACK_DIR/." "$target/"
    write_rollback_metadata "$target"
    printf '%s\n' "$backup_id" > "$BACKUP_ROOT/latest"
    chmod 600 "$BACKUP_ROOT/latest"
    rotate_persistent_backups
    log "last-known-good backup saved: $backup_id"
}

resolve_persistent_backup() {
    local requested="$1"
    if [[ "$requested" == "latest" ]]; then
        [[ -f "$BACKUP_ROOT/latest" && ! -L "$BACKUP_ROOT/latest" ]] || \
            fail "no last-known-good backup is available"
        read -r requested < "$BACKUP_ROOT/latest"
    fi
    [[ "$requested" =~ ^backup-[0-9]{8}T[0-9]{6}Z-[0-9]+(-[0-9]+)?$ ]] || \
        fail "invalid rollback backup id"
    local selected="$BACKUP_ROOT/$requested"
    [[ -d "$selected" && ! -L "$selected" ]] || \
        fail "rollback backup does not exist: $requested"
    printf '%s\n' "$selected"
}

verify_rollback_backup() {
    local backup_dir="$1"
    [[ -f "$backup_dir/rollback.meta" && ! -L "$backup_dir/rollback.meta" ]] || \
        fail "rollback metadata is missing or unsafe"
    [[ -f "$backup_dir/SHA256SUMS" && ! -L "$backup_dir/SHA256SUMS" ]] || \
        fail "rollback checksums are missing or unsafe"
    grep -Fqx 'format=anytls-panel-rollback-v1' "$backup_dir/rollback.meta" || \
        fail "unsupported rollback backup format"
    (cd "$backup_dir" && sha256sum --check --quiet SHA256SUMS) || \
        fail "rollback backup checksum verification failed"
}

load_rollback_metadata() {
    local metadata="$ROLLBACK_DIR/rollback.meta"
    local variable value
    for variable in \
        OLD_PANEL_UNIT_PRESENT OLD_PANEL_ACTIVE OLD_PANEL_ENABLED \
        OLD_PANEL_ENABLEMENT_MANAGED OLD_CADDY_UNIT_PRESENT OLD_CADDY_ACTIVE \
        OLD_CADDY_ENABLED OLD_CADDY_ENABLEMENT_MANAGED \
        OLD_HEALTH_TIMER_UNIT_PRESENT OLD_HEALTH_TIMER_ACTIVE \
        OLD_HEALTH_TIMER_ENABLED OLD_HEALTH_TIMER_ENABLEMENT_MANAGED \
        OLD_INSTALL_PRESENT CODE_BACKED_UP DATABASE_BACKED_UP \
        DATABASE_STATE_CAPTURED CONFIG_BACKED_UP; do
        value="$(sed -n "s/^${variable}=//p" "$metadata")"
        [[ "$value" =~ ^[01]$ ]] || fail "invalid rollback metadata: $variable"
        printf -v "$variable" '%s' "$value"
    done
}

list_persistent_backups() {
    if [[ ! -d "$BACKUP_ROOT" ]]; then
        log "no persistent backups"
        return
    fi
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d \
        -name 'backup-*' -printf '%f\n' | sort -r
}

delayed_rollback() {
    local requested="${1:-latest}"
    validate_configuration
    validate_supported_os
    validate_install_target
    validate_service_target
    ensure_runtime
    ensure_service_user

    local selected selected_copy current_snapshot
    selected="$(resolve_persistent_backup "$requested")"
    selected_copy="$(mktemp -d "${PANEL_DIR%/*}/.${SERVICE_NAME}-delayed-rollback.XXXXXX")"
    chmod 700 "$selected_copy"
    cp -a -- "$selected/." "$selected_copy/"
    verify_rollback_backup "$selected_copy"

    begin_cutover
    current_snapshot="$ROLLBACK_DIR"
    persist_rollback_backup
    ROLLBACK_DIR="$selected_copy"
    load_rollback_metadata
    CUTOVER_STARTED=1
    ROLLBACK_FINISHED=0
    if ! rollback_deployment; then
        fail "delayed rollback failed; the pre-rollback snapshot remains in $BACKUP_ROOT"
    fi
    rm -rf -- "$current_snapshot"
    DEPLOY_SUCCEEDED=1
    log "delayed rollback completed from ${selected##*/}"
}

rollback_step() {
    local description="$1"
    shift
    if ! "$@" >/dev/null 2>&1; then
        printf '[anytls-panel] ERROR: rollback step failed: %s\n' "$description" >&2
        ROLLBACK_FAILED=1
    fi
}

rollback_systemd_unit_exists() {
    local unit="$1"
    local status
    if systemd_unit_exists "$unit"; then
        return 0
    else
        status=$?
    fi
    if [[ "$status" -eq 2 ]]; then
        printf '[anytls-panel] ERROR: rollback could not inspect systemd unit: %s\n' \
            "$unit" >&2
        ROLLBACK_FAILED=1
    fi
    return "$status"
}

stop_unit_for_rollback_if_present() {
    local description="$1"
    local unit="$2"
    if rollback_systemd_unit_exists "$unit"; then
        rollback_step "$description" systemctl stop "$unit"
    fi
    return 0
}

disable_unit_if_previously_disabled() {
    local unit="$1"
    local was_enabled="$2"
    local enablement_managed="$3"
    if [[ "$was_enabled" -eq 0 && "$enablement_managed" -eq 1 ]] && \
       rollback_systemd_unit_exists "$unit"; then
        rollback_step "disable $unit" systemctl disable "$unit"
    fi
    return 0
}

enable_unit_if_previously_enabled() {
    local unit="$1"
    local was_enabled="$2"
    local enablement_managed="$3"
    if [[ "$was_enabled" -eq 1 && "$enablement_managed" -eq 1 ]]; then
        rollback_step "enable $unit" systemctl enable "$unit"
    fi
}

restore_unit_activity() {
    local unit="$1"
    local was_present="$2"
    local was_active="$3"
    local description="$4"
    if [[ "$was_present" -eq 0 ]]; then
        stop_unit_for_rollback_if_present "keep $description stopped" "$unit"
    elif [[ "$was_active" -eq 1 ]]; then
        rollback_step "start $description" systemctl start "$unit"
    else
        rollback_step "keep $description stopped" systemctl stop "$unit"
    fi
}

rollback_deployment() {
    [[ "${ROLLBACK_FINISHED:-0}" -eq 0 ]] || return 0
    ROLLBACK_FAILED=0
    printf '[anytls-panel] deployment failed; restoring the previous release\n' >&2

    stop_unit_for_rollback_if_present \
        "stop health-check timer" "${SERVICE_NAME}-healthcheck.timer"
    stop_unit_for_rollback_if_present "stop panel" "$SERVICE_NAME"
    stop_unit_for_rollback_if_present "stop Caddy" caddy
    disable_unit_if_previously_disabled \
        "$SERVICE_NAME" "$OLD_PANEL_ENABLED" "$OLD_PANEL_ENABLEMENT_MANAGED"
    disable_unit_if_previously_disabled \
        caddy "$OLD_CADDY_ENABLED" "$OLD_CADDY_ENABLEMENT_MANAGED"
    disable_unit_if_previously_disabled \
        "${SERVICE_NAME}-healthcheck.timer" "$OLD_HEALTH_TIMER_ENABLED" \
        "$OLD_HEALTH_TIMER_ENABLEMENT_MANAGED"

    if [[ "$CODE_BACKED_UP" -eq 1 && -d "$PANEL_DIR" ]]; then
        rollback_step "remove incomplete release" \
            find "$PANEL_DIR" -mindepth 1 -maxdepth 1 ! -name data \
                -exec rm -rf -- {} +
        if [[ -d "$ROLLBACK_DIR/code" ]]; then
            while IFS= read -r -d '' entry; do
                rollback_step "restore release file ${entry##*/}" \
                    mv -- "$entry" "$PANEL_DIR/"
            done < <(find "$ROLLBACK_DIR/code" -mindepth 1 -maxdepth 1 -print0)
        fi
    fi
    if [[ "$OLD_INSTALL_PRESENT" -eq 0 ]]; then
        rollback_step "remove new installation marker" \
            rm -f -- "$PANEL_DIR/.anytls-panel-install"
    fi

    if [[ "$DATABASE_STATE_CAPTURED" -eq 1 ]]; then
        rollback_step "remove failed database" \
            rm -f -- "$DATA_DIR/anytls.db" "$DATA_DIR/anytls.db-wal" \
                "$DATA_DIR/anytls.db-shm"
        if [[ "$DATABASE_BACKED_UP" -eq 1 ]]; then
            rollback_step "restore database" \
                cp -a -- "$ROLLBACK_DIR/anytls.db" "$DATA_DIR/anytls.db"
            rollback_step "restore database ownership" \
                chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR/anytls.db"
            rollback_step "restore database permissions" \
                chmod 600 "$DATA_DIR/anytls.db"
        fi
    fi

    if [[ "$CONFIG_BACKED_UP" -eq 1 ]]; then
        rollback_step "restore panel service" restore_optional_file \
            "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" panel.service
        rollback_step "restore Caddyfile" restore_optional_file \
            "$CADDYFILE" Caddyfile
        rollback_step "restore Caddy site" restore_optional_file \
            "$CADDY_SITES_DIR/${SERVICE_NAME}.caddy" caddy-site
        rollback_step "restore health-check script" restore_optional_file \
            "$HEALTHCHECK_SCRIPT" healthcheck-script
        rollback_step "restore health-check service" restore_optional_file \
            "$HEALTHCHECK_SERVICE" healthcheck.service
        rollback_step "restore health-check timer" restore_optional_file \
            "$HEALTHCHECK_TIMER" healthcheck.timer
        rollback_step "restore Caddy restart policy" restore_optional_file \
            "$CADDY_RESTART_DROPIN" caddy-restart.conf
        rollback_step "restore session secret" restore_optional_file \
            "$SECRET_KEY_FILE" secret-key
        rollback_step "restore traffic token" restore_optional_file \
            "$TRAFFIC_API_TOKEN_FILE" traffic-api-token
        rollback_step "restore admin password" restore_optional_file \
            "$ADMIN_PASSWORD_FILE" admin-password
        rollback_step "restore data marker" restore_optional_file \
            "$DATA_DIR/.anytls-panel-data" data-marker
    fi

    rollback_step "reload systemd" systemctl daemon-reload
    enable_unit_if_previously_enabled \
        "$SERVICE_NAME" "$OLD_PANEL_ENABLED" "$OLD_PANEL_ENABLEMENT_MANAGED"
    enable_unit_if_previously_enabled \
        caddy "$OLD_CADDY_ENABLED" "$OLD_CADDY_ENABLEMENT_MANAGED"
    enable_unit_if_previously_enabled \
        "${SERVICE_NAME}-healthcheck.timer" "$OLD_HEALTH_TIMER_ENABLED" \
        "$OLD_HEALTH_TIMER_ENABLEMENT_MANAGED"
    restore_unit_activity \
        "$SERVICE_NAME" "$OLD_PANEL_UNIT_PRESENT" "$OLD_PANEL_ACTIVE" panel
    restore_unit_activity \
        caddy "$OLD_CADDY_UNIT_PRESENT" "$OLD_CADDY_ACTIVE" Caddy
    restore_unit_activity \
        "${SERVICE_NAME}-healthcheck.timer" \
        "$OLD_HEALTH_TIMER_UNIT_PRESENT" "$OLD_HEALTH_TIMER_ACTIVE" \
        "health-check timer"
    if [[ "$ROLLBACK_FAILED" -ne 0 ]]; then
        printf '[anytls-panel] ERROR: rollback incomplete; manual recovery required\n' >&2
        return 1
    fi
    CUTOVER_STARTED=0
    ROLLBACK_FINISHED=1
    printf '[anytls-panel] previous release restored successfully\n' >&2
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

copy_release_files() {
    local source_dir="$1"
    local destination_dir="$2"
    local manifest="$source_dir/release-files.txt"
    [[ -f "$manifest" && ! -L "$manifest" ]] || \
        fail "release source is missing a safe release-files.txt manifest"

    local entry source_path destination_path current_path component
    local path_components=()
    while IFS= read -r entry || [[ -n "$entry" ]]; do
        [[ -n "$entry" && "$entry" != \#* ]] || continue
        case "$entry" in
            /*|.|./*|*/./*|*/.|..|../*|*/../*|*/..|*//* )
                fail "unsafe path in release-files.txt: $entry"
                ;;
        esac
        if ! [[ "$entry" =~ ^[A-Za-z0-9._/-]+$ ]]; then
            fail "invalid path in release-files.txt: $entry"
        fi
        source_path="$source_dir/$entry"
        destination_path="$destination_dir/$entry"
        current_path="$source_dir"
        IFS='/' read -r -a path_components <<< "$entry"
        for component in "${path_components[@]}"; do
            current_path="$current_path/$component"
            [[ ! -L "$current_path" ]] || \
                fail "release manifest path must not traverse symlinks: $entry"
        done
        [[ -f "$source_path" && ! -L "$source_path" ]] || \
            fail "release manifest entry is not a regular file: $entry"
        install -d -m 755 "${destination_path%/*}"
        cp -a -- "$source_path" "$destination_path"
    done < "$manifest"
}

copy_directory_contents() {
    local source_dir="$1"
    local destination_dir="$2"
    local entry
    while IFS= read -r -d '' entry; do
        cp -a "$entry" "$destination_dir/"
    done < <(find "$source_dir" -mindepth 1 -maxdepth 1 -print0)
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
        copy_release_files "$SCRIPT_DIR" "$RELEASE_SOURCE"
    else
        log "fetching project from $REPO_URL ($REPO_REF) before stopping the service"
        local clone_dir="$STAGE_DIR/clone"
        git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$clone_dir" -q
        local source_dir="$clone_dir"
        if [[ -n "$REPO_SUBDIR" ]]; then
            source_dir="$clone_dir/$REPO_SUBDIR"
        fi
        [[ -d "$source_dir" ]] || fail "project source directory not found: $source_dir"
        copy_release_files "$source_dir" "$RELEASE_SOURCE"
    fi

    for required_file in \
        app.py database_maintenance.py db_migrations.py input_limits.py \
        node_probe.py protocol_codecs.py security_utils.py sqlite_rate_limit.py \
        traffic_token.py requirements.txt; do
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

prepare_smoke_database() {
    local target_database="$1"
    local source_database=""
    local candidate
    for candidate in "$DATA_DIR/anytls.db" "$PANEL_DIR/anytls.db"; do
        if [[ -e "$candidate" || -L "$candidate" ]]; then
            if [[ -L "$candidate" || ! -f "$candidate" ]]; then
                fail "existing panel database must be a regular non-symlink file"
            fi
            source_database="$candidate"
            break
        fi
    done
    [[ -n "$source_database" ]] || return 0

    log "validating the staged release against a safe copy of the existing database"
    python3 - "$source_database" "$target_database" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1], timeout=30) as source, \
     sqlite3.connect(sys.argv[2], timeout=30) as target:
    source.backup(target)
    if target.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise SystemExit('smoke database quick_check failed')
PY
    chmod 600 "$target_database"
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
    prepare_smoke_database "$smoke_dir/anytls.db"
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
assert app.get_initial_admin_credentials()[0]
PY
    )
}

install_staged_release() {
    validate_panel_dir
    mkdir -p "$PANEL_DIR"
    copy_directory_contents "$RELEASE_SOURCE" "$PANEL_DIR"
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
ExecStart=${PANEL_DIR}/venv/bin/gunicorn --workers 1 --threads 4 --no-control-socket --bind ${BIND_HOST}:${PORT} --timeout 120 app:create_app()
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=256M
TasksMax=64
LimitNOFILE=4096
ReadWritePaths=${DATA_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=ANYTLS_DATABASE=${DATA_DIR}/anytls.db
Environment=ANYTLS_SECRET_KEY_FILE=${SECRET_KEY_FILE}
Environment=ANYTLS_TRAFFIC_API_TOKEN_FILE=${TRAFFIC_API_TOKEN_FILE}
Environment=ANYTLS_SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE}
Environment=ANYTLS_TRUST_PROXY=${TRUST_PROXY}
Environment=ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=${ALLOW_PRIVATE_SUBSCRIPTIONS}
Environment=ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS=${ALLOW_HTTP_SUBSCRIPTIONS}
Environment=ANYTLS_ALLOW_PRIVATE_NODE_PROBES=${ALLOW_PRIVATE_NODE_PROBES}
Environment=ANYTLS_TRAFFIC_LOG_RETENTION_DAYS=${TRAFFIC_LOG_RETENTION_DAYS}
Environment=ANYTLS_MAX_REQUEST_BYTES=${MAX_REQUEST_BYTES}

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

STATE_DIR=/run/${SERVICE_NAME}-healthcheck
FAILURE_THRESHOLD=3
RECOVERY_COOLDOWN_SECONDS=300
install -d -o root -g root -m 700 "\$STATE_DIR"

record_probe_failure() {
    local component="\$1"
    local state_file="\$STATE_DIR/\${component}.failures"
    local count=0
    if [[ -r "\$state_file" ]]; then
        read -r count < "\$state_file" || count=0
    fi
    [[ "\$count" =~ ^[0-9]+$ ]] || count=0
    count=\$((count + 1))
    printf '%s\n' "\$count" > "\$state_file"
    logger -p daemon.warning -t ${SERVICE_NAME}-healthcheck \\
        "event=health_probe_failure component=\$component consecutive_failures=\$count"
    printf '%s\n' "\$count"
}

reset_probe_failures() {
    rm -f -- "\$STATE_DIR/\$1.failures"
}

recovery_is_suppressed() {
    local component="\$1"
    local state_file="\$STATE_DIR/\${component}.last_recovery"
    local now last_recovery=0
    now="\$(date +%s)"
    if [[ -r "\$state_file" ]]; then
        read -r last_recovery < "\$state_file" || last_recovery=0
    fi
    [[ "\$last_recovery" =~ ^[0-9]+$ ]] || last_recovery=0
    if (( now - last_recovery < RECOVERY_COOLDOWN_SECONDS )); then
        logger -p daemon.warning -t ${SERVICE_NAME}-healthcheck \\
            "event=health_recovery_suppressed component=\$component cooldown_seconds=\$RECOVERY_COOLDOWN_SECONDS"
        return 0
    fi
    printf '%s\n' "\$now" > "\$state_file"
    return 1
}

probe_backend() {
    curl --fail --silent --show-error --output /dev/null \\
        --connect-timeout 3 --max-time 8 \\
        http://127.0.0.1:${PORT}/readyz
}

probe_https() {
    curl --fail --silent --show-error --output /dev/null \\
        --connect-timeout 3 --max-time 8 \\
        --resolve ${PANEL_DOMAIN}:443:127.0.0.1 \\
        https://${PANEL_DOMAIN}/login
}

certificate_expiring() {
    ! timeout 8 openssl s_client \\
        -connect 127.0.0.1:443 -servername ${PANEL_DOMAIN} </dev/null 2>/dev/null | \\
        openssl x509 -checkend 1814400 -noout >/dev/null 2>&1
}

if ! systemctl is-active --quiet ${SERVICE_NAME} || ! probe_backend; then
    panel_failures="\$(record_probe_failure panel)"
    if (( panel_failures < FAILURE_THRESHOLD )); then
        exit 1
    fi
    recovery_is_suppressed panel && exit 1
    logger -p daemon.err -t ${SERVICE_NAME}-healthcheck \\
        'event=health_recovery component=panel action=restart'
    systemctl restart ${SERVICE_NAME}
    sleep 3
    if ! probe_backend; then
        exit 1
    fi
    reset_probe_failures panel
else
    reset_probe_failures panel
fi

if ! systemctl is-active --quiet caddy || ! probe_https; then
    caddy_failures="\$(record_probe_failure caddy)"
    if (( caddy_failures < FAILURE_THRESHOLD )); then
        exit 1
    fi
    recovery_is_suppressed caddy && exit 1
    logger -p daemon.err -t ${SERVICE_NAME}-healthcheck \\
        'event=health_recovery component=caddy action=reload-or-restart'
    systemctl reload-or-restart caddy
    sleep 3
    if ! probe_https; then
        exit 1
    fi
    reset_probe_failures caddy
else
    reset_probe_failures caddy
fi

if certificate_expiring; then
    logger -p daemon.warning -t ${SERVICE_NAME}-healthcheck \\
        'event=certificate_expiring threshold_days=21'
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
    reverse_proxy 127.0.0.1:${PORT}
}
EOF
}

caddyfile_contains_only_panel_site() {
    [[ -f "$CADDYFILE" ]] || return 1
    local compact
    compact="$(sed '/^[[:space:]]*#/d' "$CADDYFILE" | tr -d '[:space:]')"
    [[ "$compact" == "${PANEL_DOMAIN}{reverse_proxy127.0.0.1:${PORT}}" ]]
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
    fail "automatic HTTPS certificate verification timed out; check DNS and public ports 80/443"
}

start_keepalive() {
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}-healthcheck.timer" >/dev/null
    systemctl start "${SERVICE_NAME}-healthcheck.service"
    systemctl is-active --quiet "${SERVICE_NAME}-healthcheck.timer" || \
        fail "health-check timer failed to start"
}

print_summary() {
    logger -p daemon.notice -t "$SERVICE_NAME-deploy" \
        "event=deployment_success repo_ref=$REPO_REF" || true
    echo
    log "deployment succeeded"
    echo "  Panel URL:  https://${PANEL_DOMAIN}"
    echo "  HTTPS:      certificate managed and renewed automatically by Caddy"
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
    validate_supported_os
    validate_install_target
    validate_service_target
    prepare_panel_domain
    prepare_admin_credentials
    ensure_runtime
    verify_domain_resolution
    capture_caddy_state
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
    persist_rollback_backup
    DEPLOY_SUCCEEDED=1
    CUTOVER_STARTED=0
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --rollback)
            delayed_rollback "${2:-latest}"
            ;;
        --list-backups)
            [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "please run as root"
            list_persistent_backups
            ;;
        --*)
            fail "unknown option: $1"
            ;;
        *)
            main
            ;;
    esac
fi
