import base64
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = REPO_ROOT / "app.py"


def load_app(database_path):
    spec = importlib.util.spec_from_file_location("anytls_panel_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, {"ANYTLS_DATABASE": str(database_path)}, clear=False):
        spec.loader.exec_module(module)
    return module


def extract_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("csrf token not found in rendered page")
    return match.group(1)


class AnyTlsPanelTests(unittest.TestCase):
    def test_shell_scripts_use_lf_line_endings(self):
        for script in REPO_ROOT.glob("*.sh"):
            data = script.read_bytes()
            self.assertNotIn(b"\r\n", data, msg=f"{script.name} uses CRLF line endings")

    def test_traffic_collector_counts_only_its_accounting_rules(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
iptables() {{
    if [ "$1" = "-L" ] && [ "$2" = "INPUT" ]; then
        printf '%s\\n' \
            '0 100 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:443' \
            '0 200 tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:443 /* anytls-panel-traffic-in-443 */'
        return 0
    fi
    if [ "$1" = "-L" ] && [ "$2" = "OUTPUT" ]; then
        printf '%s\\n' \
            '0 30 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp spt:443' \
            '0 40 tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp spt:443 /* anytls-panel-traffic-out-443 */'
        return 0
    fi
    return 0
}}
curl() {{ return 0; }}
source "{script}"
get_traffic_bytes
"""

        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)

        self.assertEqual(result.stdout.strip(), "240")

    def test_traffic_collector_adds_non_accepting_commented_rules(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
iptables() {{
    if [ "$1" = "-C" ]; then return 1; fi
    printf '%s\\n' "$*"
}}
source "{script}"
ensure_iptables
"""
        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)

        self.assertIn("-I INPUT", result.stdout)
        self.assertIn("--comment anytls-panel-traffic-in-443", result.stdout)
        self.assertIn("--comment anytls-panel-traffic-out-443", result.stdout)
        self.assertNotIn("-j ACCEPT", result.stdout)

    def test_traffic_collector_preserves_cumulative_total_across_counter_reset(self):
        script = REPO_ROOT / "traffic_collector.sh"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "traffic.state"
            state.write_text("100 1000\n", encoding="utf-8")
            probe = f"""
TRAFFIC_STATE_FILE="{state}"
source "{script}"
ensure_iptables() {{ :; }}
get_traffic_bytes() {{ printf '%s\\n' "$CURRENT_BYTES"; }}
report_traffic() {{ printf 'reported=%s\\n' "$1"; }}
CURRENT_BYTES=125
main
CURRENT_BYTES=20
main
printf 'state='
cat "$TRAFFIC_STATE_FILE"
"""
            result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)

        self.assertEqual(result.stdout.splitlines(), [
            "reported=1025",
            "reported=1045",
            "state=20 1045",
        ])

    def test_clash_yaml_subscription_returns_nodes_and_traffic_tuple(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            nodes, traffic_info = app.parse_subscribe_url(
                """
proxies:
  - name: Good Trojan
    type: trojan
    server: example.com
    port: 443
    password: secret
  - name: Bad Port
    type: trojan
    server: bad.example
    port: not-a-number
    password: bad
"""
            )

        self.assertEqual(traffic_info, {})
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "Good Trojan")
        self.assertEqual(nodes[0]["protocol"], "trojan")

    def test_clash_yaml_null_ws_options_do_not_drop_later_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            nodes = app._parse_clash_yaml(
                """
proxies:
  - name: VMess without ws options
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    network: ws
    ws-opts:
  - name: Later Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: secret
"""
            )

        self.assertEqual([node["name"] for node in nodes], [
            "VMess without ws options",
            "Later Trojan",
        ])

    def test_http_subscription_prefers_native_anytls_user_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            seen_user_agents = []

            def fake_read(_url, user_agent):
                seen_user_agents.append(user_agent)
                return b"anytls://pw@example.com:443#demo"

            with mock.patch.object(app, "_assert_public_subscription_url"):
                with mock.patch.object(app, "_read_subscription_url", side_effect=fake_read):
                    nodes, traffic_info = app.parse_subscribe_url("https://sub.example/list")

        self.assertEqual(traffic_info, {})
        self.assertIn("SSRVPN", seen_user_agents[0])
        self.assertEqual(nodes[0]["protocol"], "anytls")
        self.assertTrue(nodes[0]["raw_uri"].startswith("anytls://"))

    def test_http_subscription_selects_later_mixed_protocol_candidate(self):
        clash_trojan_only = b"""
proxies:
  - name: compat
    type: trojan
    server: compat.example.com
    port: 443
    password: compat
"""
        shadowrocket_native = base64.b64encode(
            b"anytls://native@native.example.com:443#native\n"
            b"trojan://compat@compat.example.com:443#compat"
        )

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            seen_user_agents = []

            def fake_read(_url, user_agent):
                seen_user_agents.append(user_agent)
                if "SSRVPN" in user_agent or "Clash.Meta" in user_agent:
                    raise OSError("blocked")
                if "ClashForAndroid" in user_agent:
                    return clash_trojan_only
                return shadowrocket_native

            with mock.patch.object(app, "_assert_public_subscription_url"):
                with mock.patch.object(app, "_read_subscription_url", side_effect=fake_read):
                    nodes, traffic_info = app.parse_subscribe_url("https://sub.example/list")

        self.assertEqual(traffic_info, {})
        self.assertTrue(any("Shadowrocket" in ua for ua in seen_user_agents))
        self.assertFalse(any("ClashForAndroid" in ua for ua in seen_user_agents))
        self.assertEqual(len(nodes), 2)
        self.assertEqual([node["protocol"] for node in nodes], ["anytls", "trojan"])
        self.assertTrue(nodes[0]["raw_uri"].startswith("anytls://"))
        self.assertTrue(nodes[1]["raw_uri"].startswith("trojan://"))

    def test_http_subscription_rejects_private_network_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            private_result = [
                (2, 1, 6, "", ("127.0.0.1", 80)),
            ]
            with mock.patch("socket.getaddrinfo", return_value=private_result):
                with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network called")):
                    with mock.patch("urllib.request.build_opener") as build_opener:
                        with self.assertRaisesRegex(ValueError, "公网"):
                            app.parse_subscribe_url("http://internal.example/sub")

        build_opener.assert_not_called()

    def test_http_subscription_limits_response_size(self):
        class OversizedResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"x" * (2 * 1024 * 1024 + 1)

            def geturl(self):
                return "https://sub.example/list"

        class FakeOpener:
            def open(self, _request, timeout=10):
                self.timeout = timeout
                return OversizedResponse()

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = [
                (2, 1, 6, "", ("93.184.216.34", 443)),
            ]
            with mock.patch("socket.getaddrinfo", return_value=public_result):
                with mock.patch("urllib.request.build_opener", return_value=FakeOpener()):
                    with self.assertRaisesRegex(ValueError, "响应过大"):
                        app._read_subscription_url("https://sub.example/list", "SSRVPN/2.4.0")

    def test_http_subscription_rejects_redirects_to_private_networks(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            request = mock.Mock(full_url="https://sub.example/list")
            private_result = [
                (2, 1, 6, "", ("169.254.169.254", 80)),
            ]
            with mock.patch("socket.getaddrinfo", return_value=private_result):
                with self.assertRaisesRegex(ValueError, "公网"):
                    app._SafeSubscriptionRedirectHandler().redirect_request(
                        request,
                        None,
                        302,
                        "Found",
                        {},
                        "http://metadata.example/latest",
                    )

    def test_initial_admin_credentials_can_be_set_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_ADMIN_USER": "Elegy",
                    "ANYTLS_ADMIN_PASS": "strong-password",
                },
                clear=False,
            ):
                app = load_app(database)

            db = sqlite3.connect(app.app.config["DATABASE"])
            row = db.execute("SELECT username, password_hash FROM admin_users").fetchone()
            db.close()

        self.assertEqual(row[0], "Elegy")
        ok, needs_upgrade = app.verify_password(row[1], "strong-password")
        self.assertTrue(ok)
        self.assertFalse(needs_upgrade)

    def test_initial_admin_password_is_generated_without_environment_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            password_file = Path(tmp) / ".initial_admin_password"
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_ADMIN_PASSWORD_FILE": str(password_file),
                },
                clear=False,
            ):
                os.environ.pop("ANYTLS_ADMIN_PASS", None)
                app = load_app(database)

            generated_password = password_file.read_text(encoding="utf-8").strip()
            db = sqlite3.connect(app.app.config["DATABASE"])
            row = db.execute("SELECT username, password_hash FROM admin_users").fetchone()
            db.close()

        self.assertEqual(row[0], "admin")
        self.assertNotEqual(generated_password, "admin123")
        ok, _ = app.verify_password(row[1], generated_password)
        self.assertTrue(ok)
        weak_ok, _ = app.verify_password(row[1], "admin123")
        self.assertFalse(weak_ok)

    def test_secret_key_and_database_are_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            secret_key_file = Path(tmp) / ".secret_key"
            with mock.patch.dict(
                os.environ,
                {"ANYTLS_SECRET_KEY_FILE": str(secret_key_file)},
                clear=False,
            ):
                app = load_app(database)

            self.assertEqual(secret_key_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)
            self.assertTrue(app.app.secret_key)

    def test_private_file_creation_is_atomic_across_threads(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            secret_file = Path(tmp) / "shared-secret"

            def create_value():
                time.sleep(0.02)
                return f"secret-{threading.get_ident()}"

            with ThreadPoolExecutor(max_workers=8) as executor:
                values = list(executor.map(
                    lambda _index: app._read_or_create_private_file(secret_file, create_value),
                    range(8),
                ))
            file_value = secret_file.read_text(encoding="utf-8")
            file_mode = secret_file.stat().st_mode & 0o777

        self.assertEqual(len(set(values)), 1)
        self.assertEqual(file_value, values[0])
        self.assertEqual(file_mode, 0o600)

    def test_concurrent_database_initialization_creates_one_admin(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            with sqlite3.connect(database) as db:
                db.execute("DELETE FROM admin_users")
                db.commit()
            barrier = threading.Barrier(4)

            def synchronized_hash(_password):
                barrier.wait(timeout=2)
                return "test-hash"

            with mock.patch.object(app, "hash_password", side_effect=synchronized_hash):
                with ThreadPoolExecutor(max_workers=4) as executor:
                    list(executor.map(lambda _index: app.init_db(), range(4)))

            with sqlite3.connect(database) as db:
                admin_count = db.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]

        self.assertEqual(admin_count, 1)

    def test_secure_cookie_and_proxy_mode_are_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_SESSION_COOKIE_SECURE": "1",
                    "ANYTLS_TRUST_PROXY": "1",
                    "ANYTLS_RATE_LIMIT_STORAGE_URI": "memory://",
                },
                clear=False,
            ):
                app = load_app(database)

        self.assertTrue(app.app.config["SESSION_COOKIE_SECURE"])
        self.assertEqual(app.limiter._storage_uri, "memory://")
        self.assertEqual(type(app.app.wsgi_app).__name__, "ProxyFix")

    def test_responses_include_baseline_security_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                response = client.get("/login", base_url="https://panel.example")

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("max-age=", response.headers["Strict-Transport-Security"])

    def test_debug_server_is_limited_to_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with mock.patch.dict(os.environ, {"DEBUG": "1", "HOST": "0.0.0.0"}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "loopback"):
                    app._development_server_options()
            with mock.patch.dict(os.environ, {"DEBUG": "1", "HOST": "127.0.0.1"}, clear=False):
                self.assertEqual(
                    app._development_server_options(),
                    ("127.0.0.1", 8866, True),
                )

    def test_generated_subscription_url_uses_current_request_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                cursor = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo"),
                )
                db.commit()
                account_id = cursor.lastrowid
            with app.app.test_client() as client:
                with client.session_transaction(base_url="https://panel.example:9443") as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                response = client.post(
                    f"/api/accounts/{account_id}/generate-token",
                    base_url="https://panel.example:9443",
                )

        payload = response.get_json()
        self.assertTrue(payload["url"].startswith("https://panel.example:9443/sub/"))

    def test_logged_in_json_post_apis_require_csrf_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
            with app.app.app_context():
                db = app.get_db()
                cursor = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo"),
                )
                db.commit()
                account_id = cursor.lastrowid

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                missing_csrf = client.post(f"/api/accounts/{account_id}/generate-token")
                self.assertEqual(missing_csrf.status_code, 400)

                page = client.get(f"/accounts/{account_id}")
                token = extract_csrf_token(page.get_data(as_text=True))
                response = client.post(
                    f"/api/accounts/{account_id}/generate-token",
                    headers={"X-CSRFToken": token},
                )

            self.assertEqual(response.status_code, 200)
            self.assertIn("/sub/", response.get_json()["url"])

    def test_traffic_api_requires_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
                },
                clear=False,
            ):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                cursor = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://node-secret@example.com:443#demo"),
                )
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        cursor.lastrowid,
                        "demo-node",
                        "example.com",
                        443,
                        "node-secret",
                        "anytls://node-secret@example.com:443#demo",
                    ),
                )
                db.commit()

            with app.app.test_client() as client:
                missing = client.post(
                    "/api/traffic/set",
                    json={"password": "node-secret", "total_bytes": 123},
                )
                bad = client.post(
                    "/api/traffic/set",
                    headers={"Authorization": "Bearer wrong-token"},
                    json={"password": "node-secret", "total_bytes": 123},
                )
                ok = client.post(
                    "/api/traffic/set",
                    headers={"Authorization": "Bearer traffic-token"},
                    json={"password": "node-secret", "total_bytes": 123},
                )

            self.assertEqual(missing.status_code, 401)
            self.assertEqual(bad.status_code, 401)
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(ok.get_json()["total_bytes"], 123)

    def test_traffic_api_rejects_invalid_payload_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
                },
                clear=False,
            ):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                cursor = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) VALUES (?, ?, ?)",
                    ("demo", "anytls://node-secret@example.com:443#demo", 100),
                )
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        cursor.lastrowid,
                        "demo-node",
                        "example.com",
                        443,
                        "node-secret",
                        "anytls://node-secret@example.com:443#demo",
                    ),
                )
                db.commit()

            headers = {"Authorization": "Bearer traffic-token"}
            with app.app.test_client() as client:
                negative = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"password": "node-secret", "bytes_used": -1},
                )
                malformed = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json=["not-object"],
                )
                fractional = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"password": "node-secret", "bytes_used": 1.5},
                )
                bad_total = client.post(
                    "/api/traffic/set",
                    headers=headers,
                    json={"password": "node-secret", "total_bytes": -1},
                )

            self.assertEqual(negative.status_code, 400)
            self.assertEqual(malformed.status_code, 400)
            self.assertEqual(fractional.status_code, 400)
            self.assertEqual(bad_total.status_code, 400)
            with sqlite3.connect(database) as db:
                used = db.execute("SELECT traffic_used_bytes FROM accounts").fetchone()[0]
            self.assertEqual(used, 100)

    def test_traffic_report_increments_without_read_modify_write(self):
        class FakeCursor:
            rowcount = 1

            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class FakeDb:
            def __init__(self):
                self.total = 100

            def execute(self, sql, params=()):
                if sql.startswith("SELECT id, traffic_used_bytes"):
                    raise AssertionError("traffic increment must not read the old total")
                if sql.startswith("UPDATE accounts SET traffic_used_bytes=COALESCE"):
                    self.total += params[0]
                    return FakeCursor()
                if sql.startswith("SELECT traffic_used_bytes FROM accounts"):
                    return FakeCursor({"traffic_used_bytes": self.total})
                if sql.startswith("INSERT INTO traffic_logs"):
                    return FakeCursor()
                raise AssertionError(f"unexpected SQL: {sql}")

            def commit(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(Path(tmp) / "anytls.db"),
                    "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
                },
                clear=False,
            ):
                app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            fake_db = FakeDb()
            with mock.patch.object(app, "get_db", return_value=fake_db):
                with app.app.test_client() as client:
                    response = client.post(
                        "/api/traffic/report",
                        headers={"Authorization": "Bearer traffic-token"},
                        json={"account_id": 1, "bytes_used": 50},
                    )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["results"][0]["total_bytes"], 150)

    def test_account_forms_reject_invalid_traffic_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, traffic_limit_gb) VALUES (?, ?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo", 250),
                ).lastrowid
                db.commit()

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                response = client.post(
                    f"/accounts/{account_id}/edit",
                    data={
                        "subscribe_url": "anytls://pw@example.com:443#demo",
                        "traffic_limit_gb": "not-a-number",
                        "status": "active",
                    },
                )

            self.assertEqual(response.status_code, 302)
            with sqlite3.connect(database) as db:
                limit = db.execute("SELECT traffic_limit_gb FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
            self.assertEqual(limit, 250)

    def test_account_sync_stores_parsed_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "trojan://pw@example.com:443?sni=example.com#demo"),
                ).lastrowid
                db.commit()

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                response = client.post(f"/accounts/{account_id}/sync")

            self.assertEqual(response.status_code, 302)
            with sqlite3.connect(database) as db:
                protocol, raw_uri = db.execute("SELECT protocol, raw_uri FROM nodes").fetchone()
            self.assertEqual(protocol, "trojan")
            self.assertTrue(raw_uri.startswith("trojan://"))

    def test_public_subscribe_sanitizes_header_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo", "token"),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "demo-node",
                        "example.com",
                        443,
                        "pw",
                        "anytls://pw@example.com:443#demo",
                    ),
                )
                db.execute(
                    "INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)",
                    ("SSRVPN.VIP", 'bad\r\nInjected: yes"name'),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get("/sub/token")

            self.assertEqual(response.status_code, 200)
            disposition = response.headers["Content-Disposition"]
            profile_title = response.headers["profile-title"]
            self.assertNotIn("\r", disposition + profile_title)
            self.assertNotIn("\n", disposition + profile_title)
            self.assertIn('filename="bad Injected: yes name"', disposition)
            self.assertNotIn('yes"name', disposition)

    def test_public_subscribe_preserves_anytls_for_ssrvpn_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    (
                        "demo",
                        "anytls://pw@example.com:443?sni=sni.example.com#demo",
                        "token",
                    ),
                )
                db.execute(
                    "INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)",
                    ("demo", "renamed"),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get(
                    "/sub/token",
                    headers={"User-Agent": "SSRVPN/2.4.0"},
                )

            self.assertEqual(response.status_code, 200)
            decoded = base64.b64decode(response.get_data(as_text=True)).decode()
            self.assertIn("anytls://pw@example.com:443", decoded)
            self.assertIn("#demo", decoded)
            self.assertNotIn("#renamed", decoded)
            self.assertNotIn("trojan://", decoded)

    def test_public_subscribe_prefers_synced_db_nodes_over_live_upstream(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("demo", "https://sub.example/list", "token"),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "demo-node",
                        "db.example.com",
                        443,
                        "dbpw",
                        "anytls://dbpw@db.example.com:443?sni=sni.example.com#demo",
                    ),
                )
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "trojan-node",
                        "trojan.example.com",
                        443,
                        "trojanpw",
                        "trojan://trojanpw@trojan.example.com:443?sni=trojan.example.com#demo-trojan",
                        "trojan",
                    ),
                )
                db.execute(
                    "INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)",
                    ("demo", "renamed"),
                )
                db.commit()

            live_trojan_nodes = [
                {
                    "name": "upstream",
                    "host": "upstream.example.com",
                    "port": 443,
                    "password": "compat",
                    "protocol": "trojan",
                    "raw_uri": "trojan://compat@upstream.example.com:443#upstream",
                }
            ]
            with mock.patch.object(app, "parse_subscribe_url", return_value=(live_trojan_nodes, {})) as parse:
                with app.app.test_client() as client:
                    response = client.get(
                        "/sub/token",
                        headers={"User-Agent": "SSRVPN/2.4.0"},
                    )

            self.assertEqual(response.status_code, 200)
            decoded = base64.b64decode(response.get_data(as_text=True)).decode()
            self.assertIn("anytls://dbpw@db.example.com:443", decoded)
            self.assertIn("trojan://trojanpw@trojan.example.com:443", decoded)
            self.assertIn("#demo", decoded)
            self.assertIn("#demo-trojan", decoded)
            self.assertNotIn("#renamed", decoded)
            parse.assert_not_called()

    def test_public_subscribe_outputs_anytls_for_clash_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    (
                        "demo",
                        "anytls://pw@example.com:443?sni=sni.example.com&allowInsecure=1&fp=chrome#demo",
                        "token",
                    ),
                )
                db.execute(
                    "INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)",
                    ("demo", "renamed"),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get(
                    "/sub/token",
                    headers={"User-Agent": "Clash.Meta/1.18.0"},
                )

            self.assertEqual(response.status_code, 200)
            content = response.get_data(as_text=True)
            self.assertIn("type: anytls", content)
            self.assertIn("password: pw", content)
            self.assertIn("sni: sni.example.com", content)
            self.assertIn("udp: true", content)
            self.assertIn("client-fingerprint: chrome", content)
            self.assertIn("skip-cert-verify: true", content)

    def test_public_clash_subscription_preserves_protocol_parameters(self):
        vmess_payload = base64.b64encode(json.dumps({
            "v": "2",
            "ps": "vmess-ws",
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "5",
            "net": "ws",
            "host": "cdn.example.com",
            "path": "/socket",
            "tls": "tls",
            "sni": "sni.example.com",
        }).encode()).decode()
        ss_userinfo = base64.b64encode(b"chacha20-ietf-poly1305:ss-password").decode()
        raw_uris = [
            ("vmess-ws", f"vmess://{vmess_payload}", "vmess"),
            ("ss-node", f"ss://{ss_userinfo}@ss.example.com:8388#ss-node", "shadowsocks"),
            (
                "trojan-node",
                "trojan://secret@trojan.example.com:443?sni=edge.example.com&allowInsecure=1#trojan-node",
                "trojan",
            ),
            (
                "vless-node",
                "vless://uuid@vless.example.com:443?security=tls&sni=vless-sni.example.com&flow=xtls-rprx-vision#vless-node",
                "vless",
            ),
            (
                "hy2-node",
                "hysteria2://auth@hy2.example.com:443?sni=hy2-sni.example.com&insecure=1#hy2-node",
                "hysteria2",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("demo", "https://sub.example/list", "token"),
                ).lastrowid
                for name, raw_uri, protocol in raw_uris:
                    parsed = app.parse_protocol_uri(
                        raw_uri,
                        "ss" if protocol == "shadowsocks" else protocol,
                    )
                    db.execute(
                        "INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            account_id,
                            name,
                            parsed["host"],
                            parsed["port"],
                            parsed["password"],
                            raw_uri,
                            protocol,
                        ),
                    )
                db.commit()

            with app.app.test_client() as client:
                response = client.get("/sub/token", headers={"User-Agent": "Clash.Meta/1.18.0"})

        import yaml
        proxies = {
            proxy["name"]: proxy
            for proxy in yaml.safe_load(response.get_data(as_text=True))["proxies"]
        }
        self.assertEqual(proxies["vmess-ws"]["alterId"], 5)
        self.assertEqual(proxies["vmess-ws"]["network"], "ws")
        self.assertEqual(proxies["vmess-ws"]["ws-opts"]["path"], "/socket")
        self.assertEqual(proxies["vmess-ws"]["ws-opts"]["headers"]["Host"], "cdn.example.com")
        self.assertTrue(proxies["vmess-ws"]["tls"])
        self.assertEqual(proxies["ss-node"]["cipher"], "chacha20-ietf-poly1305")
        self.assertEqual(proxies["trojan-node"]["sni"], "edge.example.com")
        self.assertTrue(proxies["trojan-node"]["skip-cert-verify"])
        self.assertEqual(proxies["vless-node"]["sni"], "vless-sni.example.com")
        self.assertTrue(proxies["vless-node"]["tls"])
        self.assertEqual(proxies["vless-node"]["flow"], "xtls-rprx-vision")
        self.assertEqual(proxies["hy2-node"]["sni"], "hy2-sni.example.com")
        self.assertTrue(proxies["hy2-node"]["skip-cert-verify"])

    def test_init_db_migrates_traffic_metadata_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with sqlite3.connect(database) as db:
                db.execute(
                    """CREATE TABLE accounts (
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
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        sub_token TEXT DEFAULT ''
                    )"""
                )
            load_app(database)
            with sqlite3.connect(database) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(accounts)")}

        self.assertTrue({
            "traffic_upload_bytes",
            "traffic_download_bytes",
            "expire_date",
        }.issubset(columns))

    def test_public_subscription_uses_persisted_traffic_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts ("
                    "name, subscribe_url, sub_token, traffic_limit_gb, traffic_used_bytes, "
                    "traffic_upload_bytes, traffic_download_bytes, expire_date"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "demo",
                        "anytls://pw@example.com:443#demo",
                        "token",
                        10,
                        300,
                        100,
                        200,
                        "2030-01-02",
                    ),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (account_id, "demo", "example.com", 443, "pw", "anytls://pw@example.com:443#demo"),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get("/sub/token")

        userinfo = response.headers["Subscription-Userinfo"]
        self.assertIn("upload=100", userinfo)
        self.assertIn("download=200", userinfo)
        self.assertIn("total=10737418240", userinfo)
        self.assertIn("expire=", userinfo)

    def test_account_sync_persists_traffic_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "https://sub.example/list"),
                ).lastrowid
                db.commit()

            node = {
                "name": "demo",
                "host": "example.com",
                "port": 443,
                "password": "pw",
                "raw_uri": "anytls://pw@example.com:443#demo",
                "protocol": "anytls",
            }
            traffic = {
                "used_bytes": 300,
                "upload_bytes": 100,
                "download_bytes": 200,
                "total_gb": 10,
                "expire_date": "2030-01-02",
            }
            with mock.patch.object(app, "parse_subscribe_url", return_value=([node], traffic)):
                with app.app.test_client() as client:
                    with client.session_transaction() as session:
                        session["logged_in"] = True
                        session["username"] = "admin"
                    response = client.post(f"/accounts/{account_id}/sync")

            with sqlite3.connect(database) as db:
                metadata = db.execute(
                    "SELECT traffic_used_bytes, traffic_upload_bytes, "
                    "traffic_download_bytes, traffic_limit_gb, expire_date "
                    "FROM accounts WHERE id=?",
                    (account_id,),
                ).fetchone()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(metadata, (300, 100, 200, 10, "2030-01-02"))

    def test_public_subscribe_does_not_convert_anytls_for_shadowrocket_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo", "token"),
                )
                db.execute(
                    "INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)",
                    ("demo", "renamed"),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get(
                    "/sub/token",
                    headers={"User-Agent": "Shadowrocket/2209"},
                )

            self.assertEqual(response.status_code, 200)
            decoded = base64.b64decode(response.get_data(as_text=True)).decode()
            self.assertIn("anytls://pw@example.com:443", decoded)
            self.assertIn("#demo", decoded)
            self.assertNotIn("trojan://", decoded)
            self.assertNotIn("#renamed", decoded)

    def test_api_subscribe_preserves_synced_raw_uris(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            anytls_uri = "anytls://apw@any.example.com:443?sni=any.example.com#any-node"
            trojan_uri = "trojan://tpw@trojan.example.com:443?sni=trojan.example.com#trojan-node"
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, status) VALUES (?, ?, ?)",
                    ("demo", "https://sub.example/list", "active"),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account_id, "any-node", "any.example.com", 443, "apw", anytls_uri, "anytls"),
                )
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account_id, "trojan-node", "trojan.example.com", 443, "tpw", trojan_uri, "trojan"),
                )
                db.commit()

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                response = client.get("/api/subscribe")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["links"], [anytls_uri, trojan_uri])

    def test_check_all_nodes_persists_latency(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo"),
                ).lastrowid
                node_id = db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (account_id, "node", "example.com", 443, "pw", "anytls://pw@example.com:443#demo"),
                ).lastrowid
                db.commit()

            check_result = {"online": True, "status": "online", "msg": "ok", "latency": 123}
            with mock.patch.object(app, "_check_node_connect", return_value=check_result):
                with app.app.test_client() as client:
                    with client.session_transaction() as session:
                        session["logged_in"] = True
                        session["username"] = "admin"

                    response = client.post(f"/api/accounts/{account_id}/check-all")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["results"][0]["latency"], 123)
            with sqlite3.connect(database) as db:
                is_online, latency_ms = db.execute(
                    "SELECT is_online, latency_ms FROM nodes WHERE id=?",
                    (node_id,),
                ).fetchone()
            self.assertEqual((is_online, latency_ms), (1, 123))

    def test_check_all_nodes_runs_network_probes_concurrently(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://pw@example.com:443#demo"),
                ).lastrowid
                for index in range(4):
                    db.execute(
                        "INSERT INTO nodes (account_id, name, host, port, password) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (account_id, f"node-{index}", f"node-{index}.example", 443, "pw"),
                    )
                db.commit()

            active = 0
            max_active = 0
            lock = threading.Lock()

            def slow_check(_host, _port):
                nonlocal active, max_active
                with lock:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.03)
                with lock:
                    active -= 1
                return {"online": True, "status": "online", "msg": "ok", "latency": 1}

            with mock.patch.object(app, "_check_node_connect", side_effect=slow_check):
                with app.app.test_client() as client:
                    with client.session_transaction() as session:
                        session["logged_in"] = True
                    response = client.post(f"/api/accounts/{account_id}/check-all")

        self.assertEqual(response.status_code, 200)
        self.assertGreater(max_active, 1)

    def test_sync_all_fetches_subscriptions_concurrently(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                for index in range(4):
                    db.execute(
                        "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                        (f"account-{index}", f"https://sub-{index}.example/list"),
                    )
                db.commit()

            active = 0
            max_active = 0
            lock = threading.Lock()

            def slow_parse(url):
                nonlocal active, max_active
                with lock:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.03)
                with lock:
                    active -= 1
                host = url.split("//", 1)[1].split("/", 1)[0]
                return ([{
                    "name": host,
                    "host": host,
                    "port": 443,
                    "password": "pw",
                    "raw_uri": f"anytls://pw@{host}:443#{host}",
                    "protocol": "anytls",
                }], {})

            with mock.patch.object(app, "parse_subscribe_url", side_effect=slow_parse):
                with app.app.test_client() as client:
                    with client.session_transaction() as session:
                        session["logged_in"] = True
                    response = client.post("/api/sync-all")

        self.assertEqual(response.status_code, 200)
        self.assertGreater(max_active, 1)
        self.assertTrue(all(item["status"] == "ok" for item in response.get_json()["results"]))

    def test_nodes_monitor_uses_latest_status_for_duplicate_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_ids = []
                for index in range(2):
                    account_ids.append(db.execute(
                        "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                        (f"account-{index}", f"anytls://pw{index}@shared.example:443"),
                    ).lastrowid)
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, is_online, last_checked_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account_ids[0], "older-status", "shared.example", 443, "pw0", 0, "2026-01-01 00:00:00"),
                )
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, is_online, last_checked_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (account_ids[1], "latest-status", "shared.example", 443, "pw1", 1, "2026-02-01 00:00:00"),
                )
                db.commit()

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                response = client.get("/nodes/monitor")

        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("latest-status", html)
        self.assertNotIn("older-status", html)
        self.assertIn("2 个账号", html)

    def test_check_by_host_rejects_invalid_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

            with app.app.test_client() as client:
                with client.session_transaction() as session:
                    session["logged_in"] = True
                    session["username"] = "admin"

                response = client.post(
                    "/api/check-by-host",
                    json={"host": "example.com", "port": 443.5},
                )

            self.assertEqual(response.status_code, 400)

    def test_account_detail_template_escapes_js_arguments(self):
        content = (REPO_ROOT / "templates" / "account_detail.html").read_text(encoding="utf-8")

        self.assertIn("copyText({{ n.password|tojson }})", content)
        self.assertIn("togglePw({{ n.id }}, {{ n.password|tojson }})", content)
        self.assertNotIn("copyText('{{ n.password }}')", content)
        self.assertNotIn("togglePw({{ n.id }}, '{{ n.password }}')", content)

    def test_monitor_template_does_not_embed_host_in_javascript(self):
        content = (REPO_ROOT / "templates" / "monitor.html").read_text(encoding="utf-8")

        self.assertIn('data-host="{{ n.host }}"', content)
        self.assertIn("checkOne(this.dataset.host, Number(this.dataset.port))", content)
        self.assertNotIn("checkOne('{{ n.host }}'", content)

    def test_logged_in_fetch_calls_send_csrf_header(self):
        base = (REPO_ROOT / "templates" / "base.html").read_text(encoding="utf-8")
        dashboard = (REPO_ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        detail = (REPO_ROOT / "templates" / "account_detail.html").read_text(encoding="utf-8")
        monitor = (REPO_ROOT / "templates" / "monitor.html").read_text(encoding="utf-8")

        self.assertIn("function csrfHeaders", base)
        self.assertIn("X-CSRFToken", base)
        self.assertIn("fetch('/api/sync-all', {method: 'POST', headers: csrfHeaders()}", dashboard)
        self.assertIn("generate-token", detail)
        self.assertIn("headers: csrfHeaders({'Content-Type': 'application/json'})", detail)
        self.assertIn("headers: csrfHeaders({'Content-Type': 'application/json'})", monitor)

    def test_deploy_script_supports_online_curl_mode_and_random_passwords(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn("git clone --depth 1 --branch", content)
        self.assertIn("https://github.com/Elegying/AnyTLS_Panel.git", content)
        self.assertIn("ANYTLS_REPO_SUBDIR", content)
        self.assertIn('REPO_SUBDIR="${ANYTLS_REPO_SUBDIR:-}"', content)
        self.assertNotIn("https://github.com/Elegying/SSR_Panel.git", content)
        self.assertNotIn("https://github.com/Elegying/anytls-panel.git", content)
        self.assertIn("ANYTLS_ADMIN_USER", content)
        self.assertIn("ANYTLS_ADMIN_PASS", content)
        self.assertIn("ANYTLS_TRAFFIC_API_TOKEN_FILE", content)
        self.assertIn(".traffic_api_token", content)
        self.assertIn("ANYTLS_SHOW_SECRETS", content)
        self.assertIn("ANYTLS_ADMIN_PASSWORD_FILE", content)
        self.assertIn("generate_password", content)
        self.assertIn("generate_api_token", content)
        self.assertIn('systemctl restart "$SERVICE_NAME"', content)
        self.assertIn('cp "$SCRIPT_DIR/uninstall.sh" "$PANEL_DIR/"', content)
        self.assertIn('"$SCRIPT_DIR/security_utils.py"', content)
        self.assertIn("sys.version_info >= (3, 10)", content)
        self.assertIn("Python 3.10 or newer is required", content)
        self.assertIn("mktemp -d /tmp/anytls-venv-check", content)
        self.assertIn('python3 -m venv "$probe_dir/venv"', content)
        self.assertIn('"$probe_dir/venv/bin/python" -m pip --version', content)
        self.assertIn("! -name venv", content)
        self.assertIn("--no-install-recommends", content)
        self.assertIn("APT_UPDATED=0", content)
        self.assertIn("RPM_UPDATED=0", content)
        self.assertIn("dnf", content)
        self.assertIn("yum", content)
        self.assertIn('"systemctl:systemd"', content)
        self.assertIn("python_venv_packages", content)
        self.assertIn("python3-venv python3-pip", content)
        self.assertIn("python3-pip python3-virtualenv", content)
        self.assertIn("no supported package manager found", content)
        self.assertNotIn("apt-get not found; this installer currently supports Ubuntu/Debian", content)
        self.assertNotIn("默认账号:", content)
        self.assertNotIn("默认密码:", content)

    def test_start_script_does_not_advertise_static_default_password(self):
        content = (REPO_ROOT / "start.sh").read_text(encoding="utf-8")

        self.assertNotIn("admin123", content)
        self.assertIn(".initial_admin_password", content)

    def test_production_service_uses_non_root_threaded_worker(self):
        deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
        service = (REPO_ROOT / "anytls-panel.service").read_text(encoding="utf-8")
        start = (REPO_ROOT / "start.sh").read_text(encoding="utf-8")

        for content in (deploy, service, start):
            self.assertIn("--workers 1 --threads 4", content)
            self.assertNotIn("-w 2", content)
        self.assertIn('SERVICE_USER="${ANYTLS_SERVICE_USER:-anytls-panel}"', deploy)
        self.assertIn("User=anytls-panel", service)
        self.assertNotIn("User=root", deploy + service)
        self.assertIn("NoNewPrivileges=true", deploy)
        self.assertIn("NoNewPrivileges=true", service)

    def test_uninstall_script_requires_explicit_confirmation(self):
        content = (REPO_ROOT / "uninstall.sh").read_text(encoding="utf-8")

        self.assertIn("--yes", content)
        self.assertIn("refusing to uninstall without --yes", content)
        self.assertIn("ANYTLS_SERVICE_NAME", content)


if __name__ == "__main__":
    unittest.main()
