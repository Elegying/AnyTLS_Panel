#!/usr/bin/env bash
# Create and verify root-only AnyTLS Panel disaster-recovery backups.
set -Eeuo pipefail

PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
DATA_DIR="${ANYTLS_DATA_DIR:-$PANEL_DIR/data}"
BACKUP_ROOT="${ANYTLS_BACKUP_ROOT:-/var/backups/${SERVICE_NAME}/daily}"
RETENTION_COUNT="${ANYTLS_BACKUP_RETENTION_COUNT:-14}"
SECRET_KEY_FILE="${ANYTLS_SECRET_KEY_FILE:-$DATA_DIR/.secret_key}"
TRAFFIC_API_TOKEN_FILE="${ANYTLS_TRAFFIC_API_TOKEN_FILE:-$DATA_DIR/.traffic_api_token}"
ADMIN_PASSWORD_FILE="${ANYTLS_ADMIN_PASSWORD_FILE:-$DATA_DIR/.initial_admin_password}"
DATABASE_FILE="${ANYTLS_DATABASE:-$DATA_DIR/anytls.db}"
LOCK_FILE="/run/lock/${SERVICE_NAME}-backup.lock"
PYTHON_BIN="${ANYTLS_BACKUP_PYTHON:-$PANEL_DIR/venv/bin/python}"
BACKUP_STAGING=""
BACKUP_PARTIAL=""

log() {
    printf '[anytls-panel-backup] %s\n' "$*"
}

fail() {
    printf '[anytls-panel-backup] ERROR: %s\n' "$*" >&2
    exit 1
}

validate_configuration() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "please run as root"
    [[ "$SERVICE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || \
        fail "invalid service name"
    if ! [[ "$RETENTION_COUNT" =~ ^[0-9]+$ ]] || \
       (( RETENTION_COUNT < 2 || RETENTION_COUNT > 365 )); then
        fail "ANYTLS_BACKUP_RETENTION_COUNT must be between 2 and 365"
    fi
    [[ "$BACKUP_ROOT" =~ ^/var/backups/[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || \
        fail "ANYTLS_BACKUP_ROOT must be a dedicated path below /var/backups"
    case "$BACKUP_ROOT/" in
        */../*|*/./*|*//* ) fail "ANYTLS_BACKUP_ROOT contains unsafe components" ;;
    esac
    local current="/var/backups" component
    local components=()
    IFS='/' read -r -a components <<< "${BACKUP_ROOT#/var/backups/}"
    for component in "${components[@]}"; do
        current="$current/$component"
        [[ ! -L "$current" ]] || fail "backup root must not traverse symlinks: $current"
    done
}

validate_backup_source() {
    [[ -f "$DATABASE_FILE" && ! -L "$DATABASE_FILE" ]] || \
        fail "database is missing or unsafe: $DATABASE_FILE"
    [[ -x "$PYTHON_BIN" ]] || fail "backup Python runtime is unavailable"
}

prepare_verify_python() {
    if [[ ! -x "$PYTHON_BIN" ]]; then
        PYTHON_BIN="$(command -v python3 || true)"
    fi
    [[ -n "$PYTHON_BIN" && -x "$PYTHON_BIN" ]] || \
        fail "Python 3 is required to verify a backup"
}

resolve_backup() {
    local requested="${1:-latest}"
    if [[ "$requested" == "latest" ]]; then
        [[ -f "$BACKUP_ROOT/latest" && ! -L "$BACKUP_ROOT/latest" ]] || \
            fail "no daily backup is available"
        read -r requested < "$BACKUP_ROOT/latest"
    fi
    [[ "$requested" =~ ^backup-[0-9]{8}T[0-9]{6}Z\.tar\.gz$ ]] || \
        fail "invalid backup name"
    local archive="$BACKUP_ROOT/$requested"
    [[ -f "$archive" && ! -L "$archive" ]] || fail "backup does not exist: $requested"
    printf '%s\n' "$archive"
}

verify_backup() {
    prepare_verify_python
    local archive
    archive="$(resolve_backup "${1:-latest}")"
    [[ -f "${archive}.sha256" && ! -L "${archive}.sha256" ]] || \
        fail "backup checksum is missing"
    (cd "$BACKUP_ROOT" && sha256sum --check --quiet "${archive##*/}.sha256") || \
        fail "backup archive checksum failed"
    "$PYTHON_BIN" - "$archive" <<'PY'
import hashlib
import sqlite3
import sys
import tarfile
import tempfile

archive = sys.argv[1]
allowed = {
    "anytls.db",
    "secret-key",
    "traffic-api-token",
    "initial-admin-password",
    "BACKUP-METADATA",
    "SHA256SUMS",
}
with tempfile.TemporaryDirectory(prefix="anytls-backup-verify-") as temporary:
    with tarfile.open(archive, "r:gz") as bundle:
        contents = {}
        for member in bundle.getmembers():
            name = member.name.removeprefix("./")
            if not member.isfile() or name not in allowed or "/" in name:
                raise SystemExit(f"unsafe backup member: {member.name}")
            source = bundle.extractfile(member)
            if source is None or name in contents:
                raise SystemExit(f"invalid backup member: {member.name}")
            contents[name] = source.read()
        if "anytls.db" not in contents or "SHA256SUMS" not in contents:
            raise SystemExit("backup is incomplete")
        expected = {}
        for line in contents["SHA256SUMS"].decode("utf-8").splitlines():
            digest, filename = line.split(maxsplit=1)
            expected[filename.removeprefix("./")] = digest
        if set(expected) != set(contents) - {"SHA256SUMS"}:
            raise SystemExit("backup checksum manifest is incomplete")
        for name, digest in expected.items():
            actual = hashlib.sha256(contents[name]).hexdigest()
            if actual != digest:
                raise SystemExit(f"backup member checksum failed: {name}")
        database_path = f"{temporary}/anytls.db"
        with open(database_path, "wb") as output:
            output.write(contents["anytls.db"])
    with sqlite3.connect(database_path) as connection:
        result = connection.execute("PRAGMA quick_check").fetchone()[0]
    if result != "ok":
        raise SystemExit(f"database quick_check failed: {result}")
PY
    log "verified ${archive##*/}"
}

list_backups() {
    [[ -d "$BACKUP_ROOT" ]] || return 0
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type f \
        -name 'backup-*.tar.gz' -printf '%f\n' | sort -r
}

rotate_backups() {
    local archives=()
    local remove_count index
    mapfile -t archives < <(
        find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type f \
            -name 'backup-*.tar.gz' -printf '%f\n' | sort
    )
    remove_count=$((${#archives[@]} - RETENTION_COUNT))
    (( remove_count > 0 )) || return 0
    for ((index = 0; index < remove_count; index++)); do
        rm -f -- "$BACKUP_ROOT/${archives[$index]}" \
            "$BACKUP_ROOT/${archives[$index]}.sha256"
    done
}

create_backup() {
    validate_configuration
    validate_backup_source
    install -d -o root -g root -m 700 "$BACKUP_ROOT"
    exec 9>"$LOCK_FILE"
    flock -n 9 || fail "another backup is already running"

    local timestamp backup_name archive
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup_name="backup-${timestamp}.tar.gz"
    archive="$BACKUP_ROOT/$backup_name"
    BACKUP_PARTIAL="$BACKUP_ROOT/.${backup_name}.partial"
    [[ ! -e "$archive" && ! -e "$BACKUP_PARTIAL" ]] || \
        fail "backup already exists: $backup_name"
    BACKUP_STAGING="$(mktemp -d "$BACKUP_ROOT/.staging.XXXXXX")"
    chmod 700 "$BACKUP_STAGING"
    trap 'rm -rf -- "$BACKUP_STAGING"; rm -f -- "$BACKUP_PARTIAL"' EXIT

    "$PYTHON_BIN" - "$DATABASE_FILE" "$BACKUP_STAGING/anytls.db" <<'PY'
import sqlite3
import sys

source_uri = f"file:{sys.argv[1]}?mode=ro"
with sqlite3.connect(source_uri, timeout=30, uri=True) as source, \
     sqlite3.connect(sys.argv[2], timeout=30) as target:
    source.backup(target)
    result = target.execute("PRAGMA quick_check").fetchone()[0]
if result != "ok":
    raise SystemExit(f"database quick_check failed: {result}")
PY
    chmod 600 "$BACKUP_STAGING/anytls.db"

    local source_file target_name index=0
    for source_file in "$SECRET_KEY_FILE" "$TRAFFIC_API_TOKEN_FILE" \
        "$ADMIN_PASSWORD_FILE"; do
        index=$((index + 1))
        [[ -e "$source_file" ]] || continue
        [[ -f "$source_file" && ! -L "$source_file" ]] || \
            fail "secret file is unsafe: $source_file"
        case "$index" in
            1) target_name="secret-key" ;;
            2) target_name="traffic-api-token" ;;
            3) target_name="initial-admin-password" ;;
        esac
        install -o root -g root -m 600 "$source_file" "$BACKUP_STAGING/$target_name"
    done

    {
        printf 'format=anytls-panel-disaster-backup-v1\n'
        printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if [[ -f "$PANEL_DIR/VERSION" ]]; then
            printf 'version=%s\n' "$(tr -d '\r\n' < "$PANEL_DIR/VERSION")"
        fi
        printf 'service=%s\n' "$SERVICE_NAME"
    } > "$BACKUP_STAGING/BACKUP-METADATA"
    chmod 600 "$BACKUP_STAGING/BACKUP-METADATA"
    (
        cd "$BACKUP_STAGING"
        sha256sum ./* > SHA256SUMS
        chmod 600 SHA256SUMS
        tar --sort=name --owner=0 --group=0 --numeric-owner \
            -czf "$BACKUP_PARTIAL" ./*
    )
    chmod 600 "$BACKUP_PARTIAL"
    mv -- "$BACKUP_PARTIAL" "$archive"
    BACKUP_PARTIAL=""
    (cd "$BACKUP_ROOT" && sha256sum "$backup_name" > "${backup_name}.sha256")
    chmod 600 "${archive}.sha256"
    printf '%s\n' "$backup_name" > "$BACKUP_ROOT/latest"
    chmod 600 "$BACKUP_ROOT/latest"
    rotate_backups
    verify_backup "$backup_name"
    logger -p daemon.notice -t "${SERVICE_NAME}-backup" \
        "event=backup_success archive=$backup_name" || true
    log "created $archive"
}

case "${1:-}" in
    --list)
        validate_configuration
        list_backups
        ;;
    --verify)
        validate_configuration
        verify_backup "${2:-latest}"
        ;;
    --help|-h)
        printf '%s\n' \
            'Usage: sudo backup.sh [--list | --verify [latest|backup-name]]' \
            'Without an option, creates and verifies a new root-only backup.'
        ;;
    "")
        create_backup
        ;;
    *)
        fail "unknown option: $1"
        ;;
esac
