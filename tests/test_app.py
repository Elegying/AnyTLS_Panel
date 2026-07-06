import base64
import importlib.util
import json
import os
import re
import sqlite3
import tempfile
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

    def test_http_subscription_prefers_native_anytls_user_agent(self):
        class FakeResponse:
            def __init__(self, body=b"anytls://pw@example.com:443#demo"):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            seen_user_agents = []

            def fake_urlopen(req, timeout=10):
                seen_user_agents.append(req.get_header("User-agent"))
                return FakeResponse()

            with mock.patch("urllib.request.urlopen", fake_urlopen):
                nodes, traffic_info = app.parse_subscribe_url("https://sub.example/list")

        self.assertEqual(traffic_info, {})
        self.assertIn("SSRVPN", seen_user_agents[0])
        self.assertEqual(nodes[0]["protocol"], "anytls")
        self.assertTrue(nodes[0]["raw_uri"].startswith("anytls://"))

    def test_http_subscription_selects_later_mixed_protocol_candidate(self):
        class FakeResponse:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

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

            def fake_urlopen(req, timeout=10):
                ua = req.get_header("User-agent")
                seen_user_agents.append(ua)
                if "SSRVPN" in ua or "Clash.Meta" in ua:
                    raise OSError("blocked")
                if "ClashForAndroid" in ua:
                    return FakeResponse(clash_trojan_only)
                return FakeResponse(shadowrocket_native)

            with mock.patch("urllib.request.urlopen", fake_urlopen):
                nodes, traffic_info = app.parse_subscribe_url("https://sub.example/list")

        self.assertEqual(traffic_info, {})
        self.assertTrue(any("Shadowrocket" in ua for ua in seen_user_agents))
        self.assertFalse(any("ClashForAndroid" in ua for ua in seen_user_agents))
        self.assertEqual(len(nodes), 2)
        self.assertEqual([node["protocol"] for node in nodes], ["anytls", "trojan"])
        self.assertTrue(nodes[0]["raw_uri"].startswith("anytls://"))
        self.assertTrue(nodes[1]["raw_uri"].startswith("trojan://"))

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

    def test_uninstall_script_requires_explicit_confirmation(self):
        content = (REPO_ROOT / "uninstall.sh").read_text(encoding="utf-8")

        self.assertIn("--yes", content)
        self.assertIn("refusing to uninstall without --yes", content)
        self.assertIn("ANYTLS_SERVICE_NAME", content)


if __name__ == "__main__":
    unittest.main()
