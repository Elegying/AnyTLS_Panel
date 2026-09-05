#!/usr/bin/env bash
# Runs only on a disposable Ubuntu host: real deploy, HTTPS, upgrade and rollback.
# The overrides below are called by main() in the sourced deployment script.
# SC2317/SC2329: test overrides are invoked indirectly by sourced main().
# shellcheck disable=SC1091,SC2317,SC2329
set -Eeuo pipefail

[[ "${ANYTLS_RUN_DEPLOY_E2E:-}" == 1 && "${EUID:-$(id -u)}" -eq 0 ]] || {
    echo 'Requires root and ANYTLS_RUN_DEPLOY_E2E=1 on a disposable Ubuntu 24.04 host.' >&2
    exit 1
}
# shellcheck source=/dev/null
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANYTLS_PANEL_DIR=/srv/anytls-panel-e2e
export ANYTLS_SERVICE_NAME=anytls-panel-e2e
export ANYTLS_SERVICE_USER=anytls-panel-e2e
export ANYTLS_PANEL_DOMAIN=panel.example.test
export ANYTLS_PANEL_PORT=18867
export ANYTLS_BIND_HOST=::1
export ANYTLS_ADMIN_USER=e2e-admin
export ANYTLS_ADMIN_PASS=' e2e initial password '
export ANYTLS_BACKUP_ROOT=/var/backups/anytls-panel-e2e/daily
export ANYTLS_BACKUP_RETENTION_COUNT=2
CERT_DIR=/etc/anytls-panel-e2e
[[ ! -e "$ANYTLS_PANEL_DIR" && ! -e "$CERT_DIR" ]]

cleanup() {
    if [[ -f "$ANYTLS_PANEL_DIR/.anytls-panel-install" ]]; then
        bash "$REPO_ROOT/uninstall.sh" --yes || true
    fi
    userdel "$ANYTLS_SERVICE_USER" >/dev/null 2>&1 || true
    rm -rf -- "$CERT_DIR" /var/backups/anytls-panel-e2e
    rm -f /usr/local/share/ca-certificates/anytls-panel-e2e.crt
    update-ca-certificates >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Public DNS and ACME are external to this isolated test. All HTTPS requests
# still validate a trusted test certificate, including the generated health unit.
install -d -m 755 "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=panel.example.test -addext subjectAltName=DNS:panel.example.test \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" >/dev/null 2>&1
chmod 644 "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem"
install -m 644 "$CERT_DIR/cert.pem" /usr/local/share/ca-certificates/anytls-panel-e2e.crt
update-ca-certificates >/dev/null

run_deploy() (
    scenario="${1:-}"
    set --
    # shellcheck source=../deploy.sh
    source "$REPO_ROOT/deploy.sh"
    verify_domain_resolution() { :; }
    render_caddy_site() {
        printf '%s\n' "$PANEL_DOMAIN {" \
            "    tls $CERT_DIR/cert.pem $CERT_DIR/key.pem" \
            "    reverse_proxy $(backend_address)" '}'
    }
    if [[ "$scenario" == failure ]]; then
        initialize_database() {
            "$PANEL_DIR/venv/bin/python" - "$DATA_DIR/anytls.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("UPDATE accounts SET traffic_used_bytes=999999")
PY
            return 42
        }
    fi
    if [[ "$scenario" == rollback ]]; then
        delayed_rollback latest
    else
        main
    fi
)

verify_runtime() {
    systemctl is-active --quiet "$ANYTLS_SERVICE_NAME" caddy \
        "$ANYTLS_SERVICE_NAME-healthcheck.timer" "$ANYTLS_SERVICE_NAME-backup.timer"
    curl --fail --silent --show-error 'http://[::1]:18867/readyz'
    curl --fail --silent --show-error --output /dev/null \
        --resolve panel.example.test:443:127.0.0.1 https://panel.example.test/login
    runuser -u "$ANYTLS_SERVICE_USER" -- "$ANYTLS_PANEL_DIR/venv/bin/python" - \
        "$ANYTLS_PANEL_DIR/data/anytls.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    assert db.execute('PRAGMA foreign_key_check').fetchall() == []
    assert db.execute('SELECT name, traffic_used_bytes, sub_token FROM accounts').fetchone() == (
        'e2e-proof', 123, 'e2e-stable-subscription'
    )
PY
}

run_deploy
"$ANYTLS_PANEL_DIR/venv/bin/python" - "$REPO_ROOT/tests" <<'PY'
import os
import sys
import unittest
# Deployment fixture credentials and paths must not leak into independent tests.
for key in list(os.environ):
    if key.startswith('ANYTLS_'):
        del os.environ[key]
suite = unittest.defaultTestLoader.discover(sys.argv[1], pattern='test_reliability.py')
raise SystemExit(not unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful())
PY
runuser -u "$ANYTLS_SERVICE_USER" -- "$ANYTLS_PANEL_DIR/venv/bin/python" - \
    "$ANYTLS_PANEL_DIR/data/anytls.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("INSERT INTO accounts (name, subscribe_url, traffic_used_bytes, sub_token) "
               "VALUES ('e2e-proof', 'fixture', 123, 'e2e-stable-subscription')")
PY
printf '\n# e2e previous release marker\n' >> "$ANYTLS_PANEL_DIR/app.py"
original_token_hash="$(sha256sum "$ANYTLS_PANEL_DIR/data/.traffic_api_token")"
verify_runtime

# Keep errexit active inside the sourced deployment, including its failure path.
set +e
run_deploy failure
deploy_result=$?
set -e
[[ "$deploy_result" -eq 42 ]]
grep -Fq '# e2e previous release marker' "$ANYTLS_PANEL_DIR/app.py"
verify_runtime

run_deploy
if grep -Fq '# e2e previous release marker' "$ANYTLS_PANEL_DIR/app.py"; then
    exit 1
fi
[[ "$(sha256sum "$ANYTLS_PANEL_DIR/data/.traffic_api_token")" == "$original_token_hash" ]]
verify_runtime
run_deploy rollback
grep -Fq '# e2e previous release marker' "$ANYTLS_PANEL_DIR/app.py"
verify_runtime
echo 'E2E_OK: install, trusted HTTPS, failed update, update and delayed rollback'
