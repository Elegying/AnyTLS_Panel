"""Regression checks for deployment failures and persistent credentials."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import base64
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_app import authenticate_session, load_app


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_shell(script, body, *, source_arguments=(), **environment):
    source = shlex.join([str(REPO_ROOT / script), *source_arguments])
    return subprocess.run(
        ["bash", "-c", f"source {source}\n{body}"],
        env={**os.environ, **{key: str(value) for key, value in environment.items()}},
        capture_output=True, text=True, timeout=15,
    )


class DeploymentReliabilityTests(unittest.TestCase):
    def test_backend_readiness_waits_for_startup_and_rejects_persistent_failure(self):
        result = run_shell('deploy.sh', r'''
attempts=0
curl() { ((attempts+=1)); [[ "$attempts" -eq 3 ]]; }
sleep() { :; }
wait_for_backend '[::1]:18866'
[[ "$attempts" -eq 3 ]]
curl() { return 7; }
if wait_for_backend '127.0.0.1:18866'; then exit 80; fi
if wait_for_backend 'example.com:443'; then exit 81; fi
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_secret_files_cannot_overlap(self):
        for first, second in (
            ('ANYTLS_SECRET_KEY_FILE', 'ANYTLS_TRAFFIC_API_TOKEN_FILE'),
            ('ANYTLS_SECRET_KEY_FILE', 'ANYTLS_ADMIN_PASSWORD_FILE'),
            ('ANYTLS_TRAFFIC_API_TOKEN_FILE', 'ANYTLS_ADMIN_PASSWORD_FILE'),
        ):
            result = run_shell('deploy.sh', 'validate_secret_paths', **{
                first: '/etc/anytls-panel/shared', second: '/etc/anytls-panel/shared',
            })
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('distinct files', result.stderr)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires isolated Linux root')
    def test_deploy_and_uninstall_reject_concurrent_operations(self):
        result = run_shell('deploy.sh', r'''
acquire_operation_lock
if bash -c 'source "$1"; acquire_operation_lock' _ "$SCRIPT_DIR/deploy.sh"; then
    exit 80
fi
if bash -c 'source "$1"
validate_panel_dir() { :; }
validate_install_marker() { :; }
validate_service_target() { :; }
systemctl() { exit 80; }
main --yes' _ "$SCRIPT_DIR/uninstall.sh"; then
    exit 80
fi
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count('another panel deployment'), 2, result.stderr)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires isolated Linux root')
    def test_failed_backup_verification_preserves_last_known_good(self):
        with tempfile.TemporaryDirectory(prefix="anytls-audit-", dir="/var/backups") as tmp:
            root = Path(tmp)
            with closing(sqlite3.connect(root / "anytls.db")) as db, db:
                db.execute("CREATE TABLE proof (value TEXT)")
            (root / "latest").write_text("previous-good-backup\n")
            result = run_shell("backup.sh", r'''
verify_backup() { printf 'injected verification failure\n' >&2; return 19; }
rotate_backups() { touch "$BACKUP_ROOT/rotation-was-called"; }
create_backup
''', source_arguments=("--help",), ANYTLS_PANEL_DIR=root,
                ANYTLS_DATABASE=root / "anytls.db", ANYTLS_BACKUP_ROOT=root,
                ANYTLS_BACKUP_PYTHON=sys.executable)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("injected verification failure", result.stderr)
            self.assertEqual((root / "latest").read_text(), "previous-good-backup\n")
            self.assertFalse((root / "rotation-was-called").exists())

    def test_partial_release_backup_does_not_delete_unbacked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            panel = root / "panel"
            panel.mkdir()
            for name in ("app.py", "requirements.txt", "deploy.sh"):
                (panel / name).write_text(f"original {name}")
            result = run_shell("deploy.sh", r'''
PANEL_DIR="$TEST_ROOT/panel"
ROLLBACK_DIR="$TEST_ROOT/rollback"
mkdir -p "$ROLLBACK_DIR"
OLD_INSTALL_PRESENT=1
CUTOVER_STARTED=1
systemctl() { [[ "$1" != show ]] || printf 'not-found\n'; }
copies=0
inject_backup_failure() {
    if [[ "${*: -1}" == "$ROLLBACK_DIR/code/" ]]; then
        copies=$((copies + 1))
        [[ "$copies" -ne 2 ]] || return 17
    fi
    command "$@"
}
mv() { inject_backup_failure mv "$@"; }
cp() { inject_backup_failure cp "$@"; }
backup_current_release
''', TEST_ROOT=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("previous release restored successfully", result.stderr)
            for name in ("app.py", "requirements.txt", "deploy.sh"):
                self.assertTrue((panel / name).is_file(), name)
                self.assertEqual((panel / name).read_text(), f"original {name}")

    def test_deploy_signals_restore_previous_release(self):
        for signal, exit_code in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "panel").mkdir()
                (root / "panel/app.py").write_text("new")
                (root / "rollback/code").mkdir(parents=True)
                (root / "rollback/code/app.py").write_text("old")
                result = run_shell("deploy.sh", r'''
PANEL_DIR="$TEST_ROOT/panel"
ROLLBACK_DIR="$TEST_ROOT/rollback"
OLD_INSTALL_PRESENT=1
CODE_BACKED_UP=1
CUTOVER_STARTED=1
systemctl() { [[ "$1" != show ]] || printf 'not-found\n'; }
kill -s "$TEST_SIGNAL" "$$"
''', TEST_ROOT=root, TEST_SIGNAL=signal)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual((root / "panel/app.py").read_text(), "old")

    def test_ipv6_loopback_is_used_by_all_backend_consumers(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_shell("deploy.sh", r'''
SYSTEMD_UNIT_DIR="$TEST_ROOT"
BIND_HOST=::1
PORT=18866
SERVICE_GROUP=test
PANEL_DOMAIN=panel.example.com
HEALTHCHECK_SCRIPT="$TEST_ROOT/healthcheck"
HEALTHCHECK_SERVICE="$TEST_ROOT/healthcheck.service"
HEALTHCHECK_TIMER="$TEST_ROOT/healthcheck.timer"
CADDY_RESTART_DROPIN="$TEST_ROOT/caddy/restart.conf"
validate_service_target() { :; }
install() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|-g) shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done
    command install "${args[@]}"
}
write_service
write_keepalive_config
render_caddy_site
''', TEST_ROOT=tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("reverse_proxy [::1]:18866", result.stdout)
            self.assertIn("--bind [::1]:18866", (Path(tmp) / "anytls-panel.service").read_text())
            self.assertIn("http://[::1]:18866/readyz", (Path(tmp) / "healthcheck").read_text())

    def test_update_preserves_existing_traffic_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_path = Path(tmp) / "token"
            token_path.write_text("existing-token\n")
            result = run_shell("deploy.sh", r'''
TRAFFIC_API_TOKEN_FILE="$TEST_TOKEN_FILE"
validate_secret_paths() { :; }
prepare_traffic_api_token
''', TEST_TOKEN_FILE=token_path, ANYTLS_TRAFFIC_API_TOKEN="new-unintended-token")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(token_path.read_text(), "existing-token\n")

    def test_collector_separates_similar_ports_and_large_counters(self):
        result = run_shell("traffic_collector.sh", r'''
iptables() {
    if [[ "$2" == INPUT ]]; then
        printf '%s\n' \
          '0 1234567890123 tcp /* anytls-panel-traffic-in-443 */' \
          '0 999999 tcp /* anytls-panel-traffic-in-4430 */'
    else
        printf '%s\n' \
          '0 2345678901234 tcp /* anytls-panel-traffic-out-443 */' \
          '0 999999 tcp /* anytls-panel-traffic-out-4430 */'
    fi
}
get_traffic_bytes
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "3580246791357")


class CredentialReliabilityTests(unittest.TestCase):
    def test_status_metadata_keeps_correct_units_and_sqlite_integer_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            self.assertEqual(app._parse_status_line("STATUS=TOT:1048576KB")['total_gb'], 1)
            info = app._parse_status_line("STATUS=↑:99999999999999TB,↓:1GB")
            self.assertNotIn('upload_bytes', info)
            self.assertNotIn('used_bytes', info)
            self.assertEqual(info['download_bytes'], 1024**3)

    def test_invalid_vmess_fields_never_reach_database_bindings(self):
        from protocol_codecs import parse_protocol_uri

        valid = {"ps": "test", "add": "node.example.com", "port": 443, "id": "test-uuid"}
        for changes in ({"ps": []}, {"add": {}}, {"id": []}, {"port": 0}, {"port": 65536}):
            with self.subTest(changes=changes):
                uri = "vmess://" + base64.b64encode(json.dumps({**valid, **changes}).encode()).decode()
                self.assertIsNone(parse_protocol_uri(uri, "vmess"))

    def test_initialization_fails_when_password_cannot_be_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            Path(tmp, ".initial_admin_password").unlink()
            with mock.patch.object(app, "_read_or_create_private_file", side_effect=PermissionError):
                with self.assertRaises(RuntimeError):
                    app.get_initial_admin_credentials()

    def test_password_with_edge_spaces_survives_initialization_and_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / ".initial_admin_password"
            password_file.write_text(" initial password \n")
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.test_client() as client:
                login = client.post("/login", data={
                    "username": "admin", "password": " initial password ",
                })
                self.assertEqual(login.status_code, 302)
                changed = client.post("/settings/password", data={
                    "old_password": " initial password ",
                    "new_password": " replacement password ",
                    "confirm_password": " replacement password ",
                })
                self.assertEqual(changed.status_code, 302)
                login = client.post("/login", data={
                    "username": "admin", "password": " replacement password ",
                })
                self.assertEqual(login.status_code, 302)

    def test_password_file_is_cleaned_after_application_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            password_file = Path(tmp) / ".initial_admin_password"
            old_password = password_file.read_text().strip()
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.test_client() as client:
                authenticate_session(app, client)
                client.post("/settings/password", data={
                    "old_password": old_password,
                    "new_password": "replacement-password",
                    "confirm_password": "replacement-password",
                })
            self.assertFalse(password_file.exists())

    def test_concurrent_token_creation_returns_one_persistent_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            barrier = threading.Barrier(2)

            def generate(_length):
                barrier.wait(timeout=5)
                return f"token-{threading.get_ident()}"

            with mock.patch.object(app.secrets, "token_urlsafe", side_effect=generate):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    tokens = list(pool.map(lambda _: app.get_traffic_api_token(), range(2)))
            self.assertEqual(len(set(tokens)), 1)
            token_file = Path(tmp) / ".traffic_api_token"
            self.assertEqual(token_file.read_text().strip(), tokens[0])
            self.assertEqual(token_file.stat().st_mode & 0o777, 0o600)

    def test_non_ascii_traffic_token_is_rejected_without_server_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                response = client.post("/api/traffic/counter", json={}, headers={
                    "Authorization": "Bearer invalid-令牌",
                })
            self.assertEqual(response.status_code, 401)


class AdversarialStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / 'anytls.db'
        self.app = load_app(self.database)
        self.app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.headers = {'X-API-Token': self.app.get_traffic_api_token()}
        with closing(sqlite3.connect(self.database)) as db, db:
            self.account_id = db.execute(
                "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes, node_count) "
                "VALUES ('adversarial', 'https://example.com/original', 10, 1)"
            ).lastrowid
            db.execute(
                "INSERT INTO nodes (account_id, name, host, port, password) "
                "VALUES (?, 'original', 'example.com', 443, 'test-password')", (self.account_id,),
            )

    def test_traffic_identity_types_are_rejected_for_every_endpoint(self):
        with self.app.app.test_client() as client:
            for endpoint, fields in (
                ('report', {'bytes_used': 1}),
                ('counter', {'counter_bytes': 1, 'collector_id': 'test-collector'}),
                ('set', {'total_bytes': 1}),
            ):
                for password in ([], {}, True, 123, ['password']):
                    with self.subTest(endpoint=endpoint, password=password):
                        response = client.post(f'/api/traffic/{endpoint}', headers=self.headers,
                                               json={**fields, 'password': password})
                        self.assertEqual(response.status_code, 400)

    def test_overflow_rolls_back_the_entire_batch_and_collector_cursor(self):
        maximum = self.app.SQLITE_INTEGER_MAX
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE accounts SET traffic_used_bytes=?', (maximum - 1,))
            db.execute('INSERT INTO traffic_collectors '
                       '(collector_id, account_id, last_counter_bytes) VALUES (?, ?, 0)',
                       ('overflow-collector', self.account_id))
        with self.app.app.test_client() as client:
            response = client.post('/api/traffic/report', headers=self.headers, json=[
                {'account_id': self.account_id, 'bytes_used': 1},
                {'account_id': self.account_id, 'bytes_used': 1},
            ])
            self.assertEqual(response.status_code, 400)
            response = client.post('/api/traffic/counter', headers=self.headers, json={
                'account_id': self.account_id, 'collector_id': 'overflow-collector',
                'counter_bytes': 2,
            })
            self.assertEqual(response.status_code, 400)
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute('SELECT traffic_used_bytes, typeof(traffic_used_bytes) '
                                        'FROM accounts').fetchone(), (maximum - 1, 'integer'))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM traffic_logs').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT last_counter_bytes FROM traffic_collectors')
                             .fetchone()[0], 0)

    def test_sync_cannot_overwrite_changes_made_while_fetching(self):
        for endpoint in (f'/accounts/{self.account_id}/sync', '/api/sync-all'):
            for field, value in (('subscribe_url', 'https://example.com/edited'),
                                 ('status', 'disabled'), ('traffic_limit_gb', 1),
                                 ('last_synced_at', '2026-09-05 00:00:00.123456')):
                with self.subTest(endpoint=endpoint, field=field):
                    with closing(sqlite3.connect(self.database)) as db, db:
                        db.execute("UPDATE accounts SET subscribe_url='https://example.com/original', "
                                   "status='active', traffic_limit_gb=250, last_synced_at=NULL")

                    def edit_then_return(_url):
                        with closing(sqlite3.connect(self.database)) as db, db:
                            db.execute(f'UPDATE accounts SET {field}=?', (value,))
                        return ([{'name': 'stale', 'host': 'example.com', 'port': 443,
                                  'password': 'stale'}], {'used_bytes': 999})

                    with mock.patch.object(self.app, 'parse_subscribe_url', side_effect=edit_then_return):
                        with self.app.app.test_client() as client:
                            authenticate_session(self.app, client)
                            response = client.post(endpoint)
                    self.assertIn(response.status_code, (200, 302))
                    if endpoint == '/api/sync-all':
                        self.assertEqual(response.get_json()['results'][0]['status'], 'skipped')
                    with closing(sqlite3.connect(self.database)) as db, db:
                        self.assertEqual(db.execute('SELECT traffic_used_bytes FROM accounts')
                                         .fetchone()[0], 10)
                        self.assertEqual(db.execute('SELECT name FROM nodes').fetchone()[0], 'original')

    def test_concurrent_renewals_only_extend_and_record_current_expiry(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            service_id = db.execute(
                "INSERT INTO customer_services "
                "(account_id, wechat_id, relationship, started_on, expires_on, sub_token) "
                "VALUES (?, 'test-only', '自用', '2026-01-01', '2027-01-01', 'test-only-token')",
                (self.account_id,),
            ).lastrowid
        barrier = threading.Barrier(6)
        parse_date = self.app.parse_iso_date

        def slow_current_date(value, field):
            if field == '当前到期日期':
                time.sleep(0.03)
            return parse_date(value, field)

        def renew(year):
            with self.app.app.test_client() as client:
                authenticate_session(self.app, client)
                barrier.wait(timeout=5)
                return client.post(f'/services/{service_id}/renew', data={
                    'new_expires_on': f'{year}-01-01',
                }).status_code

        with mock.patch.object(self.app, 'parse_iso_date', side_effect=slow_current_date):
            with ThreadPoolExecutor(max_workers=6) as pool:
                self.assertEqual(list(pool.map(renew, range(2028, 2034))), [302] * 6)
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute('SELECT expires_on FROM customer_services').fetchone()[0],
                             '2033-01-01')
            previous = '2027-01-01'
            for old, new in db.execute('SELECT old_expires_on, new_expires_on '
                                       'FROM service_renewals ORDER BY id'):
                self.assertEqual(old, previous)
                self.assertGreater(new, old)
                previous = new
