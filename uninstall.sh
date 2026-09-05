#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
CONFIRM=0
KEEP_DATA=0
SYSTEMD_UNIT_DIR="/etc/systemd/system"
CADDY_SITE_FILE="/etc/caddy/anytls-panel.d/${SERVICE_NAME}.caddy"
HEALTHCHECK_SCRIPT="/usr/local/sbin/${SERVICE_NAME}-healthcheck"
HEALTHCHECK_SERVICE="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.service"
HEALTHCHECK_TIMER="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-healthcheck.timer"
BACKUP_SERVICE="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-backup.service"
BACKUP_TIMER="${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}-backup.timer"
CADDY_RESTART_DROPIN="${SYSTEMD_UNIT_DIR}/caddy.service.d/${SERVICE_NAME}-restart.conf"

usage() {
  cat <<'EOF'
Usage: bash uninstall.sh --yes [--keep-data]

Options:
  --yes        Required. Confirm removal.
  --keep-data  Uninstall service configuration but preserve the panel directory and database.
  -h, --help   Show this help.

Environment overrides:
  ANYTLS_PANEL_DIR, ANYTLS_SERVICE_NAME
EOF
}

log() {
  printf '[anytls-panel-uninstall] %s\n' "$*"
}

fail() {
  printf '[anytls-panel-uninstall] ERROR: %s\n' "$*" >&2
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

validate_install_marker() {
  local marker="$PANEL_DIR/.anytls-panel-install"
  if [[ ! -f "$marker" || -L "$marker" ]] || \
     [[ "$(< "$marker")" != "anytls-panel-managed-v1" ]]; then
    fail "refusing to manage an unmarked directory: $PANEL_DIR"
  fi
  local marker_metadata
  if ! marker_metadata="$(stat -c '%u %a' "$marker" 2>/dev/null)"; then
    marker_metadata="$(stat -f '%u %Lp' "$marker" 2>/dev/null)" || \
      fail "cannot inspect installation marker permissions"
  fi
  local marker_owner marker_mode
  read -r marker_owner marker_mode <<< "$marker_metadata"
  if [[ "$marker_owner" != "0" ]] || (( (8#$marker_mode & 8#022) != 0 )); then
    fail "refusing to manage a directory with an untrusted installation marker"
  fi
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

main() {
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      CONFIRM=1
      ;;
    --keep-data)
      KEEP_DATA=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
  shift
done

validate_panel_dir
[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run as root"
[[ "$SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || fail "invalid service name"

if [[ "$CONFIRM" -ne 1 && "${ANYTLS_UNINSTALL_CONFIRM:-}" != "yes" ]]; then
  usage
  fail "refusing to uninstall without --yes"
fi

validate_install_marker
validate_service_target
command -v flock >/dev/null 2>&1 || fail "flock is required (install util-linux)"
exec 8>/run/anytls-panel-operation.lock
flock -n 8 || fail "another panel deployment, rollback or uninstall is running"

if [[ -L "$CADDY_SITE_FILE" ]]; then
  fail "refusing to remove a symlinked Caddy site: $CADDY_SITE_FILE"
fi
for managed_file in \
  "$HEALTHCHECK_SCRIPT" "$HEALTHCHECK_SERVICE" "$HEALTHCHECK_TIMER" \
  "$BACKUP_SERVICE" "$BACKUP_TIMER" \
  "$CADDY_RESTART_DROPIN"; do
  if [[ -L "$managed_file" ]]; then
    fail "refusing to remove a symlinked managed file: $managed_file"
  fi
done

log "disabling service: $SERVICE_NAME"
systemctl disable --now "${SERVICE_NAME}-healthcheck.timer" >/dev/null 2>&1 || true
systemctl stop "${SERVICE_NAME}-healthcheck.service" >/dev/null 2>&1 || true
systemctl disable --now "${SERVICE_NAME}-backup.timer" >/dev/null 2>&1 || true
systemctl stop "${SERVICE_NAME}-backup.service" >/dev/null 2>&1 || true
systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
rm -f "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
rm -f -- "$HEALTHCHECK_SCRIPT" "$HEALTHCHECK_SERVICE" "$HEALTHCHECK_TIMER" \
  "$BACKUP_SERVICE" "$BACKUP_TIMER" \
  "$CADDY_RESTART_DROPIN"
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ -f "$CADDY_SITE_FILE" ]]; then
  log "removing managed Caddy site"
  rm -f -- "$CADDY_SITE_FILE"
  if command -v caddy >/dev/null 2>&1 && \
     caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    systemctl reload caddy >/dev/null 2>&1 || true
  fi
fi

if [[ "$KEEP_DATA" -eq 1 ]]; then
  log "kept panel directory because --keep-data was set: $PANEL_DIR"
else
  log "removing panel directory: $PANEL_DIR"
  rm -rf -- "$PANEL_DIR"
fi

log "completed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
