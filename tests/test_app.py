import importlib.util
import json
import os
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

    def test_initial_admin_credentials_can_be_set_from_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_ADMIN_USER": "test-admin",
                    "ANYTLS_ADMIN_PASS": "strong-password",
                },
                clear=False,
            ):
                app = load_app(database)

            db = sqlite3.connect(app.app.config["DATABASE"])
            row = db.execute("SELECT username, password_hash FROM admin_users").fetchone()
            db.close()

        self.assertEqual(row[0], "test-admin")
        self.assertEqual(row[1], app.hashlib.sha256(b"strong-password").hexdigest())

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

    def test_account_detail_template_escapes_js_arguments(self):
        content = (REPO_ROOT / "templates" / "account_detail.html").read_text(encoding="utf-8")

        self.assertIn("copyText({{ n.password|tojson }})", content)
        self.assertIn("togglePw({{ n.id }}, {{ n.password|tojson }})", content)
        self.assertNotIn("copyText('{{ n.password }}')", content)
        self.assertNotIn("togglePw({{ n.id }}, '{{ n.password }}')", content)

    def test_deploy_script_supports_online_curl_mode_and_random_passwords(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn("git clone --depth 1 --branch", content)
        self.assertIn("https://github.com/Elegying/SSR_Panel.git", content)
        self.assertIn("ANYTLS_REPO_SUBDIR", content)
        self.assertIn("anytls-panel", content)
        self.assertNotIn("https://github.com/Elegying/anytls-panel.git", content)
        self.assertIn("ANYTLS_ADMIN_USER", content)
        self.assertIn("ANYTLS_ADMIN_PASS", content)
        self.assertIn("generate_password", content)
        self.assertIn('systemctl restart "$SERVICE_NAME"', content)
        self.assertIn('cp "$SCRIPT_DIR/uninstall.sh" "$PANEL_DIR/"', content)
        self.assertNotIn("默认账号:", content)
        self.assertNotIn("默认密码:", content)

    def test_uninstall_script_requires_explicit_confirmation(self):
        content = (REPO_ROOT / "uninstall.sh").read_text(encoding="utf-8")

        self.assertIn("--yes", content)
        self.assertIn("refusing to uninstall without --yes", content)
        self.assertIn("ANYTLS_SERVICE_NAME", content)


if __name__ == "__main__":
    unittest.main()
