import base64
from contextlib import closing, redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import importlib.util
import inspect
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse


REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PATH = REPO_ROOT / "app.py"


def load_app(database_path):
    spec = importlib.util.spec_from_file_location("anytls_panel_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, {"ANYTLS_DATABASE": str(database_path)}, clear=False):
        spec.loader.exec_module(module)
        module.init_db()
    return module


def extract_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not match:
        raise AssertionError("csrf token not found in rendered page")
    return match.group(1)


def authenticate_session(app, client, username="admin", base_url=None):
    with app.app.app_context():
        user = app.get_db().execute(
            "SELECT id, session_version FROM admin_users WHERE username=?",
            (username,),
        ).fetchone()
    if user is None:
        raise AssertionError(f"admin user not found: {username}")
    transaction_options = {"base_url": base_url} if base_url else {}
    with client.session_transaction(**transaction_options) as session:
        session.permanent = True
        session["logged_in"] = True
        session["username"] = username
        session["admin_user_id"] = user["id"]
        session["session_version"] = user["session_version"]


class AnyTlsPanelTests(unittest.TestCase):
    def test_shared_input_limits_reject_invalid_configuration_and_text(self):
        import input_limits

        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(input_limits.bounded_env_int("LIMIT", 7, 1, 10), 7)
        with mock.patch.dict(os.environ, {"LIMIT": "8"}, clear=True):
            self.assertEqual(input_limits.bounded_env_int("LIMIT", 7, 1, 10), 8)
        for value, message in (("invalid", "integer"), ("11", "between")):
            with self.subTest(value=value):
                with mock.patch.dict(os.environ, {"LIMIT": value}, clear=True):
                    with self.assertRaisesRegex(RuntimeError, message):
                        input_limits.bounded_env_int("LIMIT", 7, 1, 10)

        self.assertEqual(input_limits.validate_text("  ok  ", "字段", 3), "ok")
        with self.assertRaisesRegex(ValueError, "不能为空"):
            input_limits.validate_text(None, "字段", 3, required=True)
        with self.assertRaisesRegex(ValueError, "不能超过"):
            input_limits.validate_text("long", "字段", 3)

    def test_node_probe_covers_address_and_connection_failure_boundaries(self):
        import node_probe

        with self.assertRaisesRegex(ValueError, "解析结果无效"):
            node_probe._validated_addresses(["not-an-ip"], False)
        with self.assertRaisesRegex(ValueError, "无法解析"):
            node_probe._validated_addresses([], False)
        self.assertEqual(
            node_probe._validated_addresses(["fe80::1%en0", "fe80::1"], True),
            ["fe80::1"],
        )

        resolver_error = node_probe.check_node_connect(
            "node.example", 443, 1, mock.Mock(side_effect=OSError("dns failed"))
        )
        self.assertFalse(resolver_error["online"])
        self.assertEqual(resolver_error["msg"], "节点地址解析失败")

        cases = (
            (node_probe.ssl.SSLError("tls"), True, "TLS 异常"),
            (node_probe.socket.timeout(), False, "连接超时"),
            (ConnectionRefusedError(), False, "连接被拒绝"),
            (OSError("network down"), False, "连接失败"),
        )
        for failure, expected_online, expected_message in cases:
            with self.subTest(failure=type(failure).__name__):
                raw_socket = mock.Mock()
                if isinstance(failure, node_probe.ssl.SSLError):
                    context = mock.Mock()
                    context.wrap_socket.side_effect = failure
                    patches = (
                        mock.patch.object(
                            node_probe.socket, "create_connection", return_value=raw_socket
                        ),
                        mock.patch.object(
                            node_probe.ssl, "create_default_context", return_value=context
                        ),
                    )
                else:
                    patches = (
                        mock.patch.object(
                            node_probe.socket, "create_connection", side_effect=failure
                        ),
                        mock.patch.object(node_probe.ssl, "create_default_context"),
                    )
                with patches[0], patches[1]:
                    result = node_probe.check_node_connect(
                        "node.example",
                        443,
                        1,
                        lambda _host, _port, _deadline: ["8.8.8.8"],
                    )
                self.assertEqual(result["online"], expected_online)
                self.assertIn(expected_message, result["msg"])

        with mock.patch.object(node_probe.time, "monotonic", side_effect=[0, 2, 2]):
            expired = node_probe.check_node_connect(
                "node.example",
                443,
                1,
                lambda _host, _port, _deadline: ["8.8.8.8"],
            )
        self.assertEqual(expired["msg"], "连接超时")

    def test_traffic_token_cli_and_validation_fail_closed(self):
        import traffic_token

        for account_id in (True, "invalid", 0):
            with self.subTest(account_id=account_id):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    traffic_token.make_account_traffic_token("master", account_id)
        with self.assertRaisesRegex(ValueError, "empty"):
            traffic_token.make_account_traffic_token(" ", 1)

        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "token"
            token_file.write_text("master-token\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    traffic_token.main(["2", "--token-file", str(token_file)]),
                    0,
                )
            self.assertTrue(output.getvalue().startswith("atp1.2."))

            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    traffic_token.main([
                        "2", "--token-file", str(Path(tmp) / "missing")
                    ])
            token_file.write_text("\n", encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    traffic_token.main(["2", "--token-file", str(token_file)])

    def test_password_hash_legacy_and_malformed_paths(self):
        import security_utils

        legacy = hashlib.sha256(b"legacy-password").hexdigest()
        self.assertEqual(
            security_utils.verify_password(legacy, "legacy-password"),
            (True, True),
        )
        self.assertEqual(
            security_utils.verify_password(legacy, "wrong"),
            (False, False),
        )
        self.assertEqual(security_utils.verify_password("malformed", "pw"), (False, False))

    def test_migration_failure_rolls_back_version_record(self):
        import db_migrations

        with closing(sqlite3.connect(":memory:")) as db, db:
            def failing_migration(connection):
                connection.execute("CREATE TABLE should_rollback (id INTEGER)")
                raise RuntimeError("migration failed")

            with mock.patch.object(db_migrations, "_MIGRATIONS", ((99, failing_migration),)):
                with self.assertRaisesRegex(RuntimeError, "migration failed"):
                    db_migrations.apply_schema_migrations(db)
            versions = db.execute("SELECT version FROM schema_migrations").fetchall()
            table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='should_rollback'"
            ).fetchone()

        self.assertEqual(versions, [])
        self.assertIsNone(table)

    def test_database_maintenance_handles_corrupt_state_and_missing_files(self):
        import database_maintenance

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with closing(sqlite3.connect(database)) as db, db:
                db.execute(
                    "CREATE TABLE maintenance_state (key TEXT PRIMARY KEY, "
                    "value TEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
                )
                db.execute(
                    "CREATE TABLE traffic_logs (id INTEGER PRIMARY KEY, "
                    "recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
                )
                db.execute(
                    "INSERT INTO maintenance_state (key, value) "
                    "VALUES ('traffic_log_prune', 'corrupt')"
                )
                self.assertEqual(
                    database_maintenance.prune_traffic_logs(db, now=7200),
                    0,
                )
                self.assertIsInstance(database_maintenance.checkpoint_database(db), tuple)

            metrics = database_maintenance.database_metrics(database)
            missing_metrics = database_maintenance.database_metrics(
                Path(tmp) / "missing.db"
            )

        self.assertGreater(metrics["database_bytes"], 0)
        self.assertEqual(missing_metrics["database_bytes"], 0)
        self.assertEqual(missing_metrics["wal_bytes"], 0)

    def test_protocol_codecs_are_registry_driven_and_bounded(self):
        import protocol_codecs

        expected = {
            "anytls", "trojan", "vmess", "vless", "hysteria2", "tuic", "ss"
        }
        self.assertTrue(expected.issubset(protocol_codecs.CODECS))
        self.assertLessEqual(
            len(inspect.getsource(protocol_codecs.parse_clash_yaml).splitlines()),
            45,
        )
        self.assertLessEqual(
            len(inspect.getsource(protocol_codecs.clash_proxy_from_uri).splitlines()),
            30,
        )

    def test_clash_yaml_rejects_excessive_alias_expansion(self):
        import protocol_codecs

        aliases = "\n".join(f"  - *shared" for _index in range(101))
        content = "shared: &shared value\nproxies:\n" + aliases

        self.assertEqual(protocol_codecs.parse_clash_yaml(content), [])

    def test_protocol_codec_failure_paths_and_optional_fields(self):
        import protocol_codecs as codecs

        deeply_nested = "value: " + ("[" * 101) + "0" + ("]" * 101)
        self.assertEqual(codecs.parse_clash_yaml(deeply_nested), [])
        self.assertEqual(codecs.parse_clash_yaml("[]"), [])
        self.assertEqual(codecs.parse_clash_yaml("proxies: {}"), [])
        self.assertEqual(codecs.parse_clash_yaml("proxies: [invalid]"), [])
        self.assertEqual(
            codecs.parse_clash_yaml(
                "proxies:\n"
                "  - {name: bad, type: anytls, server: '', port: 443}\n"
                "  - {name: custom, type: custom, server: example.com, port: 443, password: pw}"
            )[0]["protocol"],
            "custom",
        )

        self.assertEqual(codecs._safe_int("bad", "fallback"), "fallback")
        self.assertEqual(
            codecs._sip002_split(r"one\;part;tail\\", ";"),
            [r"one\;part", r"tail\\"],
        )
        self.assertEqual(codecs._sip002_unescape("trailing\\"), "trailing\\")
        self.assertIsNone(codecs._parse_ss_uri("ss://missing-at", "ss"))
        self.assertIsNone(codecs.parse_protocol_uri("anytls://%zz@:bad", "anytls"))
        with self.assertRaisesRegex(ValueError, "invalid Clash"):
            codecs._clash_context({"type": "anytls", "server": "x", "port": 70000})

        base_node = {
            "name": "node",
            "host": "example.com",
            "port": 443,
            "password": "pw",
            "protocol": "custom",
            "extra": {},
        }
        anytls_proxy = {}
        codecs._to_anytls(
            anytls_proxy,
            base_node,
            {
                "fp": ["chrome"],
                "idleSessionCheckInterval": ["bad"],
                "idleSessionTimeout": ["30"],
                "minIdleSession": ["2"],
            },
        )
        self.assertEqual(anytls_proxy["client-fingerprint"], "chrome")
        self.assertEqual(anytls_proxy["idle-session-check-interval"], "bad")

        vmess_proxy = {}
        vmess_node = {
            **base_node,
            "extra": {
                "net": "grpc",
                "serviceName": "svc",
                "tls": "tls",
                "sni": "sni.example",
                "fp": "firefox",
                "allowInsecure": "true",
            },
        }
        codecs._to_vmess(vmess_proxy, vmess_node, {})
        self.assertEqual(vmess_proxy["grpc-opts"]["grpc-service-name"], "svc")

        ss_proxy = {}
        codecs._to_shadowsocks(
            ss_proxy,
            base_node,
            {"plugin": [r"obfs;mode=http;flag"], "pluginOpts": ["invalid"]},
        )
        self.assertTrue(ss_proxy["plugin-opts"]["flag"])
        invalid_plugin_proxy = {}
        codecs._to_shadowsocks(
            invalid_plugin_proxy,
            base_node,
            {"pluginOpts": ["not-base64-json"]},
        )
        self.assertNotIn("plugin-opts", invalid_plugin_proxy)

        trojan_proxy = {}
        codecs._to_trojan(
            trojan_proxy,
            base_node,
            {"fp": ["chrome"], "type": ["grpc"], "serviceName": ["svc"]},
        )
        self.assertEqual(trojan_proxy["grpc-opts"]["grpc-service-name"], "svc")

        vless_proxy = {}
        codecs._to_vless(
            vless_proxy,
            base_node,
            {
                "security": ["reality"],
                "pbk": ["public"],
                "sid": ["short"],
                "flow": ["vision"],
            },
        )
        self.assertEqual(vless_proxy["reality-opts"]["public-key"], "public")

        tuic_proxy = {}
        codecs._to_tuic(tuic_proxy, base_node, {})
        self.assertEqual(tuic_proxy["password"], "pw")
        unknown_proxy = {}
        codecs._to_unknown(unknown_proxy, base_node, {})
        self.assertEqual(unknown_proxy["type"], "custom")
        self.assertIsNone(codecs.clash_proxy_from_uri("not-a-uri"))

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

    def test_traffic_collector_sends_raw_counter_for_server_side_idempotency(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
COLLECTOR_ID=collector-test-raw
source "{script}"
validate_configuration() {{ :; }}
acquire_collector_lock() {{ :; }}
ensure_iptables() {{ :; }}
get_traffic_bytes() {{ printf '%s\\n' "$CURRENT_BYTES"; }}
report_traffic() {{ printf 'reported=%s\\n' "$1"; }}
CURRENT_BYTES=125
main
CURRENT_BYTES=20
main
"""
        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)

        self.assertEqual(result.stdout.splitlines(), [
            "reported=125",
            "reported=20",
        ])

    def test_traffic_collector_builds_valid_json_for_account_or_special_password(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
curl() {{
    while (( $# )); do
        if [[ "$1" == "-d" ]]; then printf '%s\\n' "$2"; return 0; fi
        shift
    done
}}
source "{script}"
COLLECTOR_ID=collector-test-123
ACCOUNT_ID=42
report_traffic 25
ACCOUNT_ID=
PASSWORD='p@ss:/"word\\tail'
report_traffic 30
"""
        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)
        payloads = [json.loads(line) for line in result.stdout.splitlines()]

        self.assertEqual(payloads[0], {
            "collector_id": "collector-test-123",
            "account_id": 42,
            "counter_bytes": 25,
        })
        password = base64.b64decode(payloads[1]["password_b64"]).decode()
        self.assertEqual(password, 'p@ss:/"word\\tail')
        self.assertEqual(payloads[1]["collector_id"], "collector-test-123")
        self.assertEqual(payloads[1]["counter_bytes"], 30)

    def test_traffic_collector_does_not_report_failed_counter_read(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
COLLECTOR_ID=collector-test-failure
source "{script}"
validate_configuration() {{ :; }}
acquire_collector_lock() {{ :; }}
ensure_iptables() {{ :; }}
iptables() {{ return 1; }}
report_traffic() {{ printf 'reported=%s\\n' "$1"; }}
main
"""
        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("reported=", result.stdout)

    def test_traffic_collector_does_not_report_when_rule_insert_fails(self):
        script = REPO_ROOT / "traffic_collector.sh"
        for failed_chain in ("INPUT", "OUTPUT"):
            with self.subTest(failed_chain=failed_chain):
                probe = f"""
COLLECTOR_ID=collector-test-rule-failure
FAILED_CHAIN={failed_chain}
source "{script}"
validate_configuration() {{ :; }}
acquire_collector_lock() {{ :; }}
iptables() {{
    if [[ "$1" == "-C" ]]; then return 1; fi
    if [[ "$1" == "-I" && "$2" == "$FAILED_CHAIN" ]]; then return 1; fi
    return 0
}}
get_traffic_bytes() {{ printf '25\n'; }}
report_traffic() {{ printf 'reported=%s\n' "$1"; }}
main
"""
                result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)

                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("reported=", result.stdout)

    def test_traffic_collector_requires_persisted_collector_id(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
COLLECTOR_ID=
COLLECTOR_ID_FILE=/dev/null/collector.id
source "{script}"
validate_configuration() {{ :; }}
acquire_collector_lock() {{ :; }}
ensure_iptables() {{ :; }}
get_traffic_bytes() {{ printf '25\n'; }}
report_traffic() {{ printf 'reported=%s\n' "$1"; }}
main
"""
        result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("reported=", result.stdout)

    def test_traffic_collector_refuses_a_second_instance(self):
        script = REPO_ROOT / "traffic_collector.sh"
        with tempfile.TemporaryDirectory() as tmp:
            lock_file = Path(tmp) / "collector.lock"
            probe = f"""
COLLECTOR_ID=collector-test-locked
COLLECTOR_LOCK_FILE="{lock_file}"
source "{script}"
validate_configuration() {{ :; }}
flock() {{ return 1; }}
validate_collector_path_parent() {{ :; }}
ensure_iptables() {{ :; }}
get_traffic_bytes() {{ printf '25\n'; }}
report_traffic() {{ printf 'reported=%s\n' "$1"; }}
main
"""
            result = subprocess.run(
                ["bash", "-c", probe], capture_output=True, text=True
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already running", result.stderr)
        self.assertNotIn("reported=", result.stdout)

    def test_traffic_collector_rejects_user_writable_state_parent(self):
        script = REPO_ROOT / "traffic_collector.sh"
        with tempfile.TemporaryDirectory() as tmp:
            unsafe_path = Path(tmp) / "collector.id"
            probe = f"""
source "{script}"
validate_collector_path_parent "{unsafe_path}" COLLECTOR_ID_FILE
"""
            result = subprocess.run(
                ["bash", "-c", probe], capture_output=True, text=True
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root-owned", result.stderr)

    def test_traffic_collector_default_lock_uses_secure_run_directory(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f"""
source "{script}"
[[ "$COLLECTOR_LOCK_FILE" == /run/anytls-panel-traffic.lock ]]
dirname() {{ printf '/run\n'; }}
realpath() {{ printf '/run\n'; }}
stat() {{ printf '0 755\n'; }}
validate_collector_path_parent "$COLLECTOR_LOCK_FILE" COLLECTOR_LOCK_FILE
printf 'accepted\n'
"""
        result = subprocess.run(
            ["bash", "-c", probe], capture_output=True, text=True
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "accepted")

    def test_traffic_collector_requires_explicit_safe_configuration(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f'''
source "{script}"
current_euid() {{ printf '0\n'; }}
command_is_available() {{ return 0; }}
PANEL_URL=
API_TOKEN=
ACCOUNT_ID=
PASSWORD=
validate_configuration
'''
        missing_url = subprocess.run(
            ["bash", "-c", probe], capture_output=True, text=True
        )

        self.assertNotEqual(missing_url.returncode, 0)
        self.assertIn("PANEL_URL is required", missing_url.stderr)

        configured_probe = f'''
source "{script}"
current_euid() {{ printf '0\n'; }}
command_is_available() {{ return 0; }}
PANEL_URL=https://panel.example.com/
API_TOKEN=test-token
ACCOUNT_ID=7
ANYTLS_PORT=8443
validate_configuration
printf 'url=%s\\n' "$PANEL_URL"
'''
        configured = subprocess.run(
            ["bash", "-c", configured_probe], capture_output=True, text=True
        )

        self.assertEqual(configured.returncode, 0, msg=configured.stderr)
        self.assertEqual(configured.stdout.strip(), "url=https://panel.example.com")

    def test_traffic_collector_rejects_insecure_remote_panel_url(self):
        script = REPO_ROOT / "traffic_collector.sh"
        probe = f'''
source "{script}"
PANEL_URL=http://panel.example.com
API_TOKEN=test-token
ACCOUNT_ID=7
validate_configuration
'''
        result = subprocess.run(
            ["bash", "-c", probe], capture_output=True, text=True
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an HTTPS origin", result.stderr)

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

    def test_clash_yaml_round_trip_preserves_key_protocol_parameters(self):
        content = r'''
proxies:
  - name: AnyTLS secure
    type: anytls
    server: any.example.com
    port: 443
    password: 'p@ss:/word'
    sni: edge.any.example
    skip-cert-verify: true
    client-fingerprint: chrome
  - name: Shadowsocks special password
    type: ss
    server: ss.example.com
    port: 8443
    cipher: chacha20-ietf-poly1305
    password: 'p@ss:/"word'
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: cdn.ss.example
  - name: Shadowsocks 2022
    type: ss
    server: ss2022.example.com
    port: 443
    cipher: 2022-blake3-aes-256-gcm
    password: 'key+/=value'
  - name: VMess websocket
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 3
    cipher: auto
    network: ws
    tls: true
    servername: tls.vmess.example
    skip-cert-verify: true
    client-fingerprint: firefox
    ws-opts:
      path: /socket
      headers:
        Host: cdn.vmess.example
  - name: VLESS websocket
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    flow: xtls-rprx-vision
    network: ws
    tls: true
    servername: tls.vless.example
    skip-cert-verify: true
    client-fingerprint: safari
    ws-opts:
      path: /vless
      headers:
        Host: cdn.vless.example
  - name: VLESS reality grpc
    type: vless
    server: reality.example.com
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    network: grpc
    tls: true
    servername: cover.example.com
    client-fingerprint: chrome
    grpc-opts:
      grpc-service-name: tunnel
    reality-opts:
      public-key: reality-public-key
      short-id: abcd1234
  - name: Hysteria2 obfs
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: hy2-secret
    sni: cover.hy2.example
    obfs: salamander
    obfs-password: obfs-secret
  - name: TUIC credentials
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 44444444-4444-4444-4444-444444444444
    password: tuic-secret
    sni: cover.tuic.example
'''
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            nodes = app._parse_clash_yaml(content)
            proxies = {
                node["name"]: app._clash_proxy_from_uri(node["raw_uri"])
                for node in nodes
            }
            raw_uris = {node["name"]: node["raw_uri"] for node in nodes}

        anytls = proxies["AnyTLS secure"]
        self.assertEqual(anytls["password"], "p@ss:/word")
        self.assertEqual(anytls["sni"], "edge.any.example")
        self.assertTrue(anytls["skip-cert-verify"])
        self.assertEqual(anytls["client-fingerprint"], "chrome")
        self.assertNotIn("idle-session-timeout", anytls)

        shadowsocks = proxies["Shadowsocks special password"]
        self.assertEqual(shadowsocks["type"], "ss")
        self.assertEqual(shadowsocks["cipher"], "chacha20-ietf-poly1305")
        self.assertEqual(shadowsocks["password"], 'p@ss:/"word')
        self.assertEqual(shadowsocks["plugin"], "v2ray-plugin")
        self.assertEqual(shadowsocks["plugin-opts"]["host"], "cdn.ss.example")
        self.assertTrue(shadowsocks["plugin-opts"]["tls"])
        ss_uri = urlparse(raw_uris["Shadowsocks special password"])
        self.assertEqual(ss_uri.path, "/")
        self.assertEqual(parse_qs(ss_uri.query), {
            "plugin": [
                "v2ray-plugin;mode=websocket;tls;host=cdn.ss.example"
            ],
        })

        shadowsocks_2022 = proxies["Shadowsocks 2022"]
        self.assertEqual(shadowsocks_2022["cipher"], "2022-blake3-aes-256-gcm")
        self.assertEqual(shadowsocks_2022["password"], "key+/=value")
        ss_2022_userinfo = urlparse(
            raw_uris["Shadowsocks 2022"]
        ).netloc.rpartition("@")[0]
        self.assertEqual(
            ss_2022_userinfo,
            "2022-blake3-aes-256-gcm:key%2B%2F%3Dvalue",
        )

        vmess = proxies["VMess websocket"]
        self.assertEqual(vmess["network"], "ws")
        self.assertEqual(vmess["ws-opts"]["path"], "/socket")
        self.assertEqual(vmess["ws-opts"]["headers"]["Host"], "cdn.vmess.example")
        self.assertEqual(vmess["servername"], "tls.vmess.example")
        self.assertTrue(vmess["skip-cert-verify"])
        self.assertEqual(vmess["client-fingerprint"], "firefox")

        vless = proxies["VLESS websocket"]
        self.assertEqual(vless["network"], "ws")
        self.assertEqual(vless["ws-opts"]["path"], "/vless")
        self.assertEqual(vless["ws-opts"]["headers"]["Host"], "cdn.vless.example")
        self.assertEqual(vless["servername"], "tls.vless.example")
        self.assertEqual(vless["flow"], "xtls-rprx-vision")
        self.assertTrue(vless["skip-cert-verify"])
        self.assertEqual(vless["client-fingerprint"], "safari")

        reality = proxies["VLESS reality grpc"]
        self.assertEqual(reality["network"], "grpc")
        self.assertEqual(reality["grpc-opts"]["grpc-service-name"], "tunnel")
        self.assertEqual(reality["reality-opts"]["public-key"], "reality-public-key")
        self.assertEqual(reality["reality-opts"]["short-id"], "abcd1234")

        hysteria = proxies["Hysteria2 obfs"]
        self.assertEqual(hysteria["obfs"], "salamander")
        self.assertEqual(hysteria["obfs-password"], "obfs-secret")

        tuic = proxies["TUIC credentials"]
        self.assertEqual(tuic["uuid"], "44444444-4444-4444-4444-444444444444")
        self.assertEqual(tuic["password"], "tuic-secret")

    def test_invalid_vmess_alter_id_does_not_break_clash_conversion(self):
        payload = base64.urlsafe_b64encode(json.dumps({
            "v": "2",
            "ps": "bad aid",
            "add": "vmess.example.com",
            "port": "443",
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": "not-a-number",
            "net": "tcp",
        }).encode()).decode().rstrip("=")
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            proxy = app._clash_proxy_from_uri(f"vmess://{payload}")

        self.assertEqual(proxy["alterId"], 0)

    def test_http_subscription_prefers_native_anytls_user_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            seen_user_agents = []

            def fake_read(_url, user_agent, _deadline=None):
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

            def fake_read(_url, user_agent, _deadline=None):
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

    def test_http_subscription_reports_sanitized_user_agent_failures(self):
        subscription_url = "https://sub.example/private-token"

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with mock.patch.object(
                app,
                "_read_subscription_url",
                side_effect=OSError("订阅服务器返回 HTTP 403"),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "SSRVPN: 订阅服务器返回 HTTP 403",
                ) as raised:
                    app.parse_subscribe_url(subscription_url)

        self.assertNotIn(subscription_url, str(raised.exception))

    def test_direct_mixed_protocol_subscription_preserves_each_scheme(self):
        content = (
            "anytls://apw@any.example.com:443#any-node\n"
            "trojan://tpw@trojan.example.com:443#trojan-node"
        )

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            nodes, traffic_info = app.parse_subscribe_url(content)

        self.assertEqual(traffic_info, {})
        self.assertEqual(
            [node["protocol"] for node in nodes],
            ["anytls", "trojan"],
        )

    def test_invalid_direct_subscription_raises_instead_of_returning_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with self.assertRaisesRegex(ValueError, "未找到可用节点"):
                app.parse_subscribe_url("anytls://invalid")

    def test_http_subscription_rejects_private_network_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            private_result = ["127.0.0.1"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=private_result,
            ):
                with mock.patch.object(
                    app.socket,
                    "create_connection",
                    side_effect=AssertionError("network called"),
                ) as connect:
                    with self.assertRaisesRegex(ValueError, "公网"):
                        app.parse_subscribe_url("https://internal.example/sub")

        connect.assert_not_called()

    def test_plain_http_subscription_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                side_effect=AssertionError("DNS should not run"),
            ) as resolve:
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    app._resolve_public_subscription_url("http://sub.example/list")

        resolve.assert_not_called()

    def test_subscription_dns_resolution_obeys_absolute_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            started = time.monotonic()
            with mock.patch.object(
                app.subprocess,
                "run",
                side_effect=app.subprocess.TimeoutExpired("resolver", 0.05),
            ):
                with self.assertRaisesRegex(TimeoutError, "订阅拉取超时"):
                    app._resolve_public_subscription_url(
                        "https://sub.example/list",
                        time.monotonic() + 0.05,
                    )

        self.assertLess(time.monotonic() - started, 0.5)

    def test_subscription_dns_resolver_runs_in_an_isolated_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            addresses = app._resolve_subscription_addresses(
                "localhost",
                443,
                time.monotonic() + 2,
            )

        self.assertTrue(addresses)
        self.assertTrue(all(isinstance(address, str) for address in addresses))

    def test_http_subscription_limits_response_size(self):
        response = mock.Mock(status=200)
        response.read1.return_value = b"x" * (2 * 1024 * 1024 + 1)
        connection = mock.Mock()
        connection.getresponse.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=public_result,
            ):
                with mock.patch.object(app.socket, "create_connection", return_value=mock.Mock()):
                    with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                        tls_context.return_value.wrap_socket.return_value = mock.Mock()
                        with mock.patch.object(
                            app.http.client,
                            "HTTPConnection",
                            return_value=connection,
                        ):
                            with self.assertRaisesRegex(ValueError, "响应过大"):
                                app._read_subscription_url(
                                    "https://sub.example/list", "SSRVPN/2.4.0"
                                )

    def test_http_subscription_stops_when_absolute_deadline_expires(self):
        response = mock.Mock(status=200)
        response.read1.side_effect = [
            b"anytls://pw@example.com:443#demo",
            b"",
        ]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        tls_socket = mock.Mock()
        clock_values = iter((0, 9, 11))

        def monotonic():
            return next(clock_values, 11)

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=public_result,
            ):
                with mock.patch.object(app.time, "monotonic", side_effect=monotonic):
                    with mock.patch.object(
                        app.socket, "create_connection", return_value=raw_socket
                    ):
                        with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                            tls_context.return_value.wrap_socket.return_value = tls_socket
                            with mock.patch.object(
                                app.http.client,
                                "HTTPConnection",
                                return_value=connection,
                            ):
                                with self.assertRaisesRegex(OSError, "连接失败"):
                                    app._read_subscription_url(
                                        "https://sub.example/list", "SSRVPN/2.4.0"
                                    )

    def test_http_redirect_does_not_read_untrusted_response_body(self):
        response = mock.Mock(status=302)
        response.getheader.return_value = "https://next.example/list"
        response.read.side_effect = AssertionError("redirect body must not be read")
        connection = mock.Mock()
        connection.getresponse.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=public_result,
            ):
                with mock.patch.object(
                    app.socket, "create_connection", return_value=mock.Mock()
                ):
                    with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                        tls_context.return_value.wrap_socket.return_value = mock.Mock()
                        with mock.patch.object(
                            app.http.client,
                            "HTTPConnection",
                            return_value=connection,
                        ):
                            _raw, redirect_url = app._read_pinned_subscription_response(
                                "https://sub.example/list", "SSRVPN/2.4.0"
                            )

        self.assertEqual(redirect_url, "https://next.example/list")
        response.read.assert_not_called()

    def test_http_subscription_rejects_redirects_to_private_networks(self):
        response = mock.Mock(status=302)
        response.getheader.return_value = "https://metadata.example/latest"
        response.read.return_value = b""
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34"]
            private_result = ["169.254.169.254"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                side_effect=[public_result, private_result],
            ):
                with mock.patch.object(app.socket, "create_connection", return_value=mock.Mock()):
                    with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                        tls_context.return_value.wrap_socket.return_value = mock.Mock()
                        with mock.patch.object(
                            app.http.client,
                            "HTTPConnection",
                            return_value=connection,
                        ):
                            with self.assertRaisesRegex(ValueError, "公网"):
                                app._read_subscription_url(
                                    "https://sub.example/list", "SSRVPN/2.4.0"
                                )

    def test_http_subscription_connects_to_the_validated_ip(self):
        response = mock.Mock(status=200)
        response.read1.side_effect = [
            b"anytls://pw@example.com:443#demo",
            b"",
        ]
        connection = mock.Mock()
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        tls_socket = mock.Mock()

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=public_result,
            ):
                with mock.patch.object(
                    app.socket, "create_connection", return_value=raw_socket
                ) as connect:
                    with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                        tls_context.return_value.wrap_socket.return_value = tls_socket
                        with mock.patch.object(
                            app.http.client,
                            "HTTPConnection",
                            return_value=connection,
                        ):
                            raw = app._read_subscription_url(
                                "https://sub.example/list", "SSRVPN/2.4.0"
                            )

        self.assertEqual(raw, b"anytls://pw@example.com:443#demo")
        self.assertEqual(connect.call_args.args[0], ("93.184.216.34", 443))
        self.assertEqual(
            tls_context.return_value.minimum_version,
            app.ssl.TLSVersion.TLSv1_2,
        )
        tls_context.return_value.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="sub.example"
        )
        connection.putheader.assert_any_call("Host", "sub.example")

    def test_http_status_does_not_retry_other_validated_ips(self):
        response = mock.Mock(status=403)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        raw_socket = mock.Mock()
        tls_socket = mock.Mock()

        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            public_result = ["93.184.216.34", "93.184.216.35"]
            with mock.patch.object(
                app,
                "_resolve_subscription_addresses",
                return_value=public_result,
            ):
                with mock.patch.object(
                    app.socket, "create_connection", return_value=raw_socket
                ) as connect:
                    with mock.patch.object(app.ssl, "create_default_context") as tls_context:
                        tls_context.return_value.wrap_socket.return_value = tls_socket
                        with mock.patch.object(
                            app.http.client,
                            "HTTPConnection",
                            return_value=connection,
                        ):
                            with self.assertRaisesRegex(OSError, "HTTP 403"):
                                app._read_pinned_subscription_response(
                                    "https://sub.example/list",
                                    "SSRVPN/2.4.0",
                                )

        self.assertEqual(connect.call_count, 1)

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
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("DELETE FROM admin_users")
                db.commit()
            barrier = threading.Barrier(4)

            def synchronized_hash(_password):
                barrier.wait(timeout=2)
                return "test-hash"

            with mock.patch.object(app, "hash_password", side_effect=synchronized_hash):
                with ThreadPoolExecutor(max_workers=4) as executor:
                    list(executor.map(lambda _index: app.init_db(), range(4)))

            with closing(sqlite3.connect(database)) as db, db:
                admin_count = db.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]

        self.assertEqual(admin_count, 1)

    def test_application_factory_owns_database_initialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            secret_key = Path(tmp) / ".secret_key"
            spec = importlib.util.spec_from_file_location(
                "anytls_panel_factory_test",
                APP_PATH,
            )
            module = importlib.util.module_from_spec(spec)
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_SECRET_KEY_FILE": str(secret_key),
                },
                clear=False,
            ):
                spec.loader.exec_module(module)
                self.assertFalse(database.exists())
                created = module.create_app()

            self.assertIs(created, module.app)
            self.assertTrue(database.is_file())

    def test_secure_cookie_and_proxy_mode_are_configurable(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with mock.patch.dict(
                os.environ,
                {
                    "ANYTLS_DATABASE": str(database),
                    "ANYTLS_SESSION_COOKIE_SECURE": "1",
                    "ANYTLS_TRUST_PROXY": "1",
                },
                clear=False,
            ):
                app = load_app(database)

        self.assertTrue(app.app.config["SESSION_COOKIE_SECURE"])
        self.assertEqual(type(app.app.wsgi_app).__name__, "ProxyFix")

    def test_login_creates_expiring_versioned_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with mock.patch.dict(
                os.environ,
                {"ANYTLS_ADMIN_PASS": "strong-review-password"},
                clear=False,
            ):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.test_client() as client:
                response = client.post(
                    "/login",
                    data={"username": "admin", "password": "strong-review-password"},
                )
                with client.session_transaction() as session:
                    permanent = session.permanent
                    user_id = session.get("admin_user_id")
                    session_version = session.get("session_version")

        cookie = response.headers["Set-Cookie"]
        self.assertEqual(response.status_code, 302)
        self.assertTrue(permanent)
        self.assertIsInstance(user_id, int)
        self.assertEqual(session_version, 1)
        self.assertIn("Expires=", cookie)
        self.assertFalse(app.app.config["SESSION_REFRESH_EACH_REQUEST"])

    def test_password_change_revokes_other_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            initial_password_file = Path(
                app.app.config["INITIAL_ADMIN_PASSWORD_FILE"]
            )
            self.assertTrue(initial_password_file.is_file())
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "UPDATE admin_users SET password_hash=? WHERE username='admin'",
                    (app.hash_password("existing-password"),),
                )
                db.commit()

            first = app.app.test_client()
            second = app.app.test_client()
            authenticate_session(app, first)
            authenticate_session(app, second)
            changed = first.post(
                "/settings/password",
                data={
                    "old_password": "existing-password",
                    "new_password": "replacement-password",
                    "confirm_password": "replacement-password",
                },
            )
            stale = second.get("/")
            self.assertFalse(initial_password_file.exists())

        self.assertEqual(changed.status_code, 302)
        self.assertTrue(changed.headers["Location"].endswith("/login"))
        self.assertEqual(stale.status_code, 302)
        self.assertTrue(stale.headers["Location"].endswith("/login"))

    def test_request_body_limit_rejects_before_form_processing(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(
                TESTING=True,
                WTF_CSRF_ENABLED=False,
                MAX_CONTENT_LENGTH=128,
            )
            with app.app.test_client() as client:
                response = client.post(
                    "/login",
                    data={"username": "admin", "password": "x" * 1024},
                )

        self.assertEqual(response.status_code, 413)
        self.assertIn("请求内容过大", response.get_data(as_text=True))

    def test_login_rate_limit_survives_application_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.test_client() as client:
                for _index in range(5):
                    response = client.post(
                        "/login",
                        data={"username": "admin", "password": "wrong"},
                    )
                    self.assertEqual(response.status_code, 200)

            reloaded = load_app(database)
            reloaded.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with reloaded.app.test_client() as client:
                response = client.post(
                    "/login",
                    data={"username": "admin", "password": "wrong"},
                )

        self.assertEqual(response.status_code, 429)
        self.assertIn("登录尝试过于频繁", response.get_data(as_text=True))

    def test_responses_include_baseline_security_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                response = client.get("/login", base_url="https://panel.example")

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("max-age=", response.headers["Strict-Transport-Security"])

    def test_responses_use_nonce_based_content_security_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                response = client.get("/login", base_url="https://panel.example")

        policy = response.headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", policy)
        self.assertRegex(policy, r"script-src 'self' 'nonce-[A-Za-z0-9_-]+'")
        self.assertIn("script-src-attr 'none'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", policy)
        nonce = re.search(r"script-src 'self' 'nonce-([^']+)'", policy).group(1)
        self.assertIn(f'<style nonce="{nonce}">', response.get_data(as_text=True))

    def test_templates_do_not_use_inline_event_handler_attributes(self):
        for template in (REPO_ROOT / "templates").glob("*.html"):
            content = template.read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(
                    r"\s(?:onclick|onsubmit|onchange|oninput|onload)\s*=",
                    content,
                    flags=re.IGNORECASE,
                ),
                msg=f"inline event handler remains in {template.name}",
            )
            for tag in re.findall(
                r"<(?:script|style)\b[^>]*>", content, flags=re.IGNORECASE
            ):
                if tag.lower().startswith("<script") and " src=" in tag:
                    continue
                self.assertIn("nonce=", tag, msg=f"missing nonce in {template.name}: {tag}")

    def test_request_id_is_validated_and_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                accepted = client.get(
                    "/login", headers={"X-Request-ID": "trace-123_A"}
                )
                replaced = client.get(
                    "/login", headers={"X-Request-ID": "x" * 200}
                )

        self.assertEqual(accepted.headers["X-Request-ID"], "trace-123_A")
        self.assertNotEqual(replaced.headers["X-Request-ID"], "x" * 200)
        self.assertRegex(replaced.headers["X-Request-ID"], r"^[a-f0-9]{32}$")

    def test_health_endpoints_are_loopback_only_and_readiness_checks_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with app.app.test_client() as client:
                health = client.get(
                    "/healthz", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
                )
                ready = client.get(
                    "/readyz", environ_overrides={"REMOTE_ADDR": "::1"}
                )
                external = client.get(
                    "/healthz",
                    environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
                )

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json(), {"status": "ok"})
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(ready.get_json()["schema_version"], app.SCHEMA_VERSION)
        self.assertEqual(external.status_code, 404)

    def test_readiness_fails_closed_when_database_check_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with mock.patch.object(
                app, "get_db", side_effect=sqlite3.OperationalError("unavailable")
            ):
                with app.app.test_client() as client:
                    response = client.get(
                        "/readyz",
                        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
                    )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})

    def test_readiness_fails_closed_when_database_disk_is_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True)
            with mock.patch.object(
                app,
                "database_metrics",
                return_value={"database_bytes": 1, "wal_bytes": 0, "free_bytes": 1024},
            ):
                with app.app.test_client() as client:
                    response = client.get(
                        "/readyz",
                        environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
                    )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"status": "unavailable"})

    def test_login_audit_log_excludes_passwords(self):
        password = "do-not-log-this-password"
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with self.assertLogs("anytls.audit", level="INFO") as captured:
                with app.app.test_client() as client:
                    client.post(
                        "/login",
                        data={"username": "admin", "password": password},
                    )

        output = "\n".join(captured.output)
        self.assertIn('"action":"auth.login"', output)
        self.assertIn('"outcome":"failure"', output)
        self.assertNotIn(password, output)

        with app.app.test_request_context(
            "/login", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
        ):
            app.g.request_id = "request-id"
            with self.assertLogs("anytls.audit", level="INFO") as sanitized:
                app.audit_event(
                    "auth.login", "failure", username="admin\nforged-entry"
                )
        payload = json.loads(sanitized.records[0].getMessage())
        self.assertEqual(payload["username"], "adminforged-entry")

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
                authenticate_session(
                    app, client, base_url="https://panel.example:9443"
                )

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
                authenticate_session(app, client)

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

    def test_account_scoped_traffic_token_cannot_update_other_accounts(self):
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
                account_ids = [
                    db.execute(
                        "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                        (f"account-{index}", f"anytls://pw{index}@example.com:443"),
                    ).lastrowid
                    for index in range(2)
                ]
                db.commit()
                scoped_token = app.generate_account_traffic_token(account_ids[0])

            headers = {"Authorization": f"Bearer {scoped_token}"}
            with app.app.test_client() as client:
                own = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"account_id": account_ids[0], "bytes_used": 25},
                )
                other = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"account_id": account_ids[1], "bytes_used": 1000},
                )
                password_identity = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"password": "pw0", "bytes_used": 1000},
                )

            with closing(sqlite3.connect(database)) as db, db:
                totals = [row[0] for row in db.execute(
                    "SELECT traffic_used_bytes FROM accounts ORDER BY id"
                )]

        self.assertEqual(own.status_code, 200)
        self.assertEqual(other.status_code, 403)
        self.assertEqual(password_identity.status_code, 403)
        self.assertEqual(totals, [25, 0])

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
                bad_account_id = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"account_id": True, "bytes_used": 1},
                )
                oversized_integer = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"password": "node-secret", "bytes_used": 2**63},
                )
                oversized_batch = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json=[
                        {"password": "node-secret", "bytes_used": 1}
                        for _index in range(app.MAX_TRAFFIC_BATCH_ITEMS + 1)
                    ],
                )

            self.assertEqual(negative.status_code, 400)
            self.assertEqual(malformed.status_code, 400)
            self.assertEqual(fractional.status_code, 400)
            self.assertEqual(bad_total.status_code, 400)
            self.assertEqual(bad_account_id.status_code, 400)
            self.assertEqual(oversized_integer.status_code, 400)
            self.assertEqual(oversized_batch.status_code, 413)
            with closing(sqlite3.connect(database)) as db, db:
                used = db.execute("SELECT traffic_used_bytes FROM accounts").fetchone()[0]
            self.assertEqual(used, 100)

    def test_traffic_set_never_lowers_total_and_missing_account_is_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "ANYTLS_DATABASE": str(database),
                "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
            }, clear=False):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) VALUES (?, ?, ?)",
                    ("demo", "anytls://pw@example.com:443", 1000),
                ).lastrowid
                db.commit()

            headers = {"Authorization": "Bearer traffic-token"}
            with app.app.test_client() as client:
                lower = client.post(
                    "/api/traffic/set",
                    headers=headers,
                    json={"account_id": account_id, "total_bytes": 20},
                )
                missing = client.post(
                    "/api/traffic/set",
                    headers=headers,
                    json={"account_id": 999999, "total_bytes": 20},
                )

            with closing(sqlite3.connect(database)) as db, db:
                total = db.execute(
                    "SELECT traffic_used_bytes FROM accounts WHERE id=?", (account_id,)
                ).fetchone()[0]

        self.assertEqual(lower.status_code, 200)
        self.assertEqual(lower.get_json()["total_bytes"], 1000)
        self.assertEqual(total, 1000)
        self.assertEqual(missing.status_code, 404)

    def test_traffic_password_must_identify_exactly_one_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "ANYTLS_DATABASE": str(database),
                "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
            }, clear=False):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_ids = []
                for index in range(2):
                    account_id = db.execute(
                        "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) VALUES (?, ?, ?)",
                        (f"account-{index}", "anytls://same@example.com:443", 0),
                    ).lastrowid
                    account_ids.append(account_id)
                    db.execute(
                        "INSERT INTO nodes (account_id, name, host, port, password) VALUES (?, ?, ?, ?, ?)",
                        (account_id, f"node-{index}", f"node-{index}.example", 443, "same"),
                    )
                db.commit()

            headers = {"Authorization": "Bearer traffic-token"}
            with app.app.test_client() as client:
                ambiguous = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"password": "same", "bytes_used": 50},
                )
                explicit = client.post(
                    "/api/traffic/report",
                    headers=headers,
                    json={"account_id": account_ids[1], "bytes_used": 50},
                )

            with closing(sqlite3.connect(database)) as db, db:
                totals = [row[0] for row in db.execute(
                    "SELECT traffic_used_bytes FROM accounts ORDER BY id"
                )]

        self.assertEqual(ambiguous.status_code, 409)
        self.assertIn("ambiguous", ambiguous.get_json()["error"])
        self.assertEqual(explicit.status_code, 200)
        self.assertEqual(totals, [0, 50])

    def test_traffic_counter_is_idempotent_and_handles_resets(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            token_file = Path(tmp) / ".traffic_api_token"
            token_file.write_text("traffic-token\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {
                "ANYTLS_DATABASE": str(database),
                "ANYTLS_TRAFFIC_API_TOKEN_FILE": str(token_file),
            }, clear=False):
                app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) VALUES (?, ?, ?)",
                    ("demo", "anytls://pw@example.com:443", 0),
                ).lastrowid
                db.commit()

            headers = {"Authorization": "Bearer traffic-token"}
            samples = [
                ("collector-one", 100),
                ("collector-one", 100),
                ("collector-one", 120),
                ("collector-one", 20),
                ("collector-two", 10),
            ]
            responses = []
            with app.app.test_client() as client:
                for collector_id, counter_bytes in samples:
                    responses.append(client.post(
                        "/api/traffic/counter",
                        headers=headers,
                        json={
                            "collector_id": collector_id,
                            "account_id": account_id,
                            "counter_bytes": counter_bytes,
                        },
                    ))

            with closing(sqlite3.connect(database)) as db, db:
                total = db.execute(
                    "SELECT traffic_used_bytes FROM accounts WHERE id=?", (account_id,)
                ).fetchone()[0]

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual([response.get_json()["delta_bytes"] for response in responses], [
            0, 0, 20, 20, 0,
        ])
        self.assertEqual(total, 40)

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
                with mock.patch.object(app, "apply_due_traffic_resets", return_value=[]):
                    with mock.patch.object(app, "prune_traffic_logs", return_value=0):
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
                authenticate_session(app, client)

                response = client.post(
                    f"/accounts/{account_id}/edit",
                    data={
                        "subscribe_url": "anytls://pw@example.com:443#demo",
                        "traffic_limit_gb": "not-a-number",
                        "status": "active",
                    },
                )

            self.assertEqual(response.status_code, 302)
            with closing(sqlite3.connect(database)) as db, db:
                limit = db.execute("SELECT traffic_limit_gb FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
            self.assertEqual(limit, 250)

    def test_admin_account_lifecycle_covers_stateful_write_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            initial_node = {
                "name": "香港入口",
                "host": "entry.example.com",
                "port": 443,
                "password": "initial-password",
                "raw_uri": "anytls://initial-password@entry.example.com:443#香港入口",
                "protocol": "anytls",
            }
            initial_traffic = {
                "total_gb": 12,
                "used_bytes": 1024,
                "upload_bytes": 256,
                "download_bytes": 768,
                "expire_date": "2030-01-02",
            }

            with app.app.test_client() as client:
                authenticate_session(app, client)
                with mock.patch.object(
                    app,
                    "parse_subscribe_url",
                    return_value=([initial_node], initial_traffic),
                ):
                    response = client.post(
                        "/accounts/add",
                        data={
                            "name": "",
                            "subscribe_url": initial_node["raw_uri"],
                            "notes": "",
                            "traffic_limit_gb": "250",
                        },
                    )
                self.assertEqual(response.status_code, 302)

                with closing(sqlite3.connect(database)) as db:
                    db.row_factory = sqlite3.Row
                    account = db.execute("SELECT * FROM accounts").fetchone()
                    node = db.execute("SELECT * FROM nodes").fetchone()
                account_id = account["id"]
                node_id = node["id"]
                self.assertEqual(account["name"], initial_node["name"])
                self.assertEqual(account["traffic_limit_gb"], 12)
                self.assertEqual(account["notes"], "到期: 2030-01-02")
                self.assertEqual(node["protocol"], "anytls")

                for path in (
                    "/",
                    "/accounts",
                    f"/accounts/{account_id}",
                    "/nodes/monitor",
                    "/settings/rename-rules",
                ):
                    self.assertEqual(client.get(path).status_code, 200)
                self.assertEqual(client.get("/api/accounts").status_code, 200)
                self.assertEqual(
                    client.get(f"/api/accounts/{account_id}/nodes").status_code,
                    200,
                )

                response = client.post(
                    f"/accounts/{account_id}/rename", data={"name": "正式账号"}
                )
                self.assertEqual(response.status_code, 302)
                response = client.post(
                    f"/accounts/{account_id}/edit",
                    data={
                        "subscribe_url": "trojan://next-password@next.example.com:8443#新加坡入口",
                        "notes": "人工维护",
                        "traffic_limit_gb": "20.5",
                        "status": "suspended",
                    },
                )
                self.assertEqual(response.status_code, 302)

                token_response = client.post(
                    f"/api/accounts/{account_id}/generate-token"
                )
                self.assertEqual(token_response.status_code, 200)
                self.assertEqual(len(token_response.get_json()["token"]), 32)

                with mock.patch.object(
                    app,
                    "_check_node_connect",
                    return_value={"online": True, "latency": 8, "msg": "在线"},
                ):
                    by_host = client.post(
                        "/api/check-by-host",
                        json={"host": initial_node["host"], "port": 443},
                    )
                    by_id = client.post(f"/api/nodes/{node_id}/check")
                self.assertEqual(by_host.status_code, 200)
                self.assertEqual(by_id.status_code, 200)

                synced_node = {
                    "name": "新加坡入口",
                    "host": "next.example.com",
                    "port": 8443,
                    "password": "next-password",
                    "raw_uri": "trojan://next-password@next.example.com:8443#新加坡入口",
                    "protocol": "trojan",
                }
                synced_traffic = {
                    "total_gb": 20.5,
                    "used_bytes": 2048,
                    "upload_bytes": 512,
                    "download_bytes": 1536,
                    "expire_date": "2030-02-03",
                }
                with mock.patch.object(
                    app,
                    "parse_subscribe_url",
                    return_value=([synced_node], synced_traffic),
                ):
                    response = client.post(f"/accounts/{account_id}/sync")
                self.assertEqual(response.status_code, 302)

                response = client.post(
                    "/settings/rename-rules/add",
                    data={"old_text": "新加坡", "new_text": "SG"},
                )
                self.assertEqual(response.status_code, 302)
                with closing(sqlite3.connect(database)) as db, db:
                    synced_node_id = db.execute("SELECT id FROM nodes").fetchone()[0]
                    rule_id = db.execute("SELECT id FROM rename_rules").fetchone()[0]
                    db.execute(
                        "INSERT INTO traffic_logs (account_id, bytes_used) VALUES (?, ?)",
                        (account_id, 100),
                    )
                    db.execute(
                        "INSERT INTO traffic_collectors "
                        "(collector_id, account_id, last_counter_bytes) VALUES (?, ?, ?)",
                        ("collector-1", account_id, 100),
                    )

                self.assertEqual(
                    client.post(f"/settings/rename-rules/{rule_id}/toggle").status_code,
                    302,
                )
                self.assertEqual(
                    client.post(f"/settings/rename-rules/{rule_id}/delete").status_code,
                    302,
                )
                self.assertEqual(
                    client.post(f"/nodes/{synced_node_id}/delete").status_code,
                    302,
                )
                self.assertEqual(
                    client.post(f"/accounts/{account_id}/delete").status_code,
                    302,
                )
                self.assertEqual(client.post("/logout").status_code, 302)

            with closing(sqlite3.connect(database)) as db:
                account_count = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
                node_count = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
                log_count = db.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
                collector_count = db.execute(
                    "SELECT COUNT(*) FROM traffic_collectors"
                ).fetchone()[0]
                rule_count = db.execute("SELECT COUNT(*) FROM rename_rules").fetchone()[0]
            self.assertEqual(
                (account_count, node_count, log_count, collector_count, rule_count),
                (0, 0, 0, 0, 0),
            )

    def test_customer_service_lifecycle_and_monthly_traffic_reset(self):
        from datetime import date

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                first_account = db.execute(
                    '''INSERT INTO accounts (
                           name, subscribe_url, traffic_limit_gb, traffic_used_bytes,
                           expire_date, last_traffic_reset_on, status, node_count
                       ) VALUES (?, ?, ?, ?, ?, ?, 'active', 1)''',
                    (
                        "upstream-one",
                        "anytls://pw1@one.example:443#one",
                        100,
                        500,
                        "2030-04-24",
                        "2026-08-24",
                    ),
                ).lastrowid
                second_account = db.execute(
                    '''INSERT INTO accounts (
                           name, subscribe_url, traffic_limit_gb, expire_date,
                           last_traffic_reset_on, status, node_count
                       ) VALUES (?, ?, ?, ?, ?, 'active', 1)''',
                    (
                        "upstream-two",
                        "anytls://pw2@two.example:443#two",
                        200,
                        "2032-05-15",
                        "2026-08-15",
                    ),
                ).lastrowid
                for account_id, host, password in (
                    (first_account, "one.example", "pw1"),
                    (second_account, "two.example", "pw2"),
                ):
                    db.execute(
                        '''INSERT INTO nodes (
                               account_id, name, host, port, password, raw_uri
                           ) VALUES (?, ?, ?, 443, ?, ?)''',
                        (
                            account_id,
                            host,
                            host,
                            password,
                            f"anytls://{password}@{host}:443#{host}",
                        ),
                    )
                db.commit()

                reset = app.traffic_reset_info(
                    "2030-04-24", today=date(2026, 9, 3)
                )
                self.assertEqual(
                    reset,
                    {
                        "day": 24,
                        "previous": "2026-08-24",
                        "next": "2026-09-24",
                        "days": 21,
                    },
                )
                self.assertEqual(
                    app.traffic_reset_info(
                        "2030-01-31", today=date(2027, 2, 1)
                    )["next"],
                    "2027-02-28",
                )
                self.assertEqual(
                    app.customer_service_state(
                        {
                            "status": "active",
                            "started_on": "2026-09-04",
                            "expires_on": "2027-09-03",
                        },
                        today=date(2026, 9, 3),
                    ),
                    "pending",
                )
                self.assertEqual(
                    set(app.apply_due_traffic_resets(db, today=date(2026, 9, 24))),
                    {first_account, second_account},
                )
                self.assertEqual(
                    db.execute(
                        "SELECT traffic_used_bytes FROM accounts WHERE id=?",
                        (first_account,),
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    app.apply_due_traffic_resets(db, today=date(2026, 9, 24)), []
                )

            with app.app.test_client() as client:
                authenticate_session(app, client)
                response = client.post(
                    "/services/add",
                    data={
                        "account_id": first_account,
                        "wechat_id": "customer-one",
                        "relationship": "借用",
                        "started_on": "2026-09-01",
                        "expires_on": "2030-05-01",
                        "notes": "annual",
                    },
                )
                self.assertEqual(response.status_code, 302)
                with closing(sqlite3.connect(database)) as db:
                    db.row_factory = sqlite3.Row
                    service = db.execute(
                        "SELECT * FROM customer_services"
                    ).fetchone()
                service_id = service["id"]
                original_token = service["sub_token"]

                self.assertEqual(client.get("/services").status_code, 200)
                detail = client.get(f"/services/{service_id}")
                self.assertEqual(detail.status_code, 200)
                self.assertIn("当前上游有效期不能完整覆盖", detail.get_data(as_text=True))
                public = client.get(f"/sub/{original_token}")
                self.assertEqual(public.status_code, 200)
                self.assertIn("expire=", public.headers["Subscription-Userinfo"])

                self.assertEqual(
                    client.post(f"/services/{service_id}/remind").status_code, 302
                )
                self.assertEqual(
                    client.post(
                        f"/services/{service_id}/renew",
                        data={"new_expires_on": "2031-05-01", "notes": "renewed"},
                    ).status_code,
                    302,
                )
                self.assertEqual(
                    client.post(
                        f"/services/{service_id}/edit",
                        data={
                            "account_id": second_account,
                            "wechat_id": "customer-one",
                            "relationship": "自用",
                            "started_on": "2026-09-01",
                            "expires_on": "2031-05-01",
                            "notes": "migrated",
                        },
                    ).status_code,
                    302,
                )
                self.assertEqual(
                    client.post(f"/services/{service_id}/rotate-token").status_code,
                    302,
                )
                with closing(sqlite3.connect(database)) as db:
                    db.row_factory = sqlite3.Row
                    updated = db.execute(
                        "SELECT * FROM customer_services WHERE id=?", (service_id,)
                    ).fetchone()
                    renewal_count = db.execute(
                        "SELECT COUNT(*) FROM service_renewals WHERE service_id=?",
                        (service_id,),
                    ).fetchone()[0]
                self.assertEqual(updated["account_id"], second_account)
                self.assertIsNone(updated["last_reminded_at"])
                self.assertNotEqual(updated["sub_token"], original_token)
                self.assertEqual(renewal_count, 1)
                self.assertEqual(client.get(f"/sub/{original_token}").status_code, 404)
                self.assertEqual(
                    client.get(f"/sub/{updated['sub_token']}").status_code, 200
                )

                self.assertEqual(
                    client.post(
                        f"/services/{service_id}/status",
                        data={"status": "suspended"},
                    ).status_code,
                    302,
                )
                self.assertEqual(
                    client.get(f"/sub/{updated['sub_token']}").status_code, 404
                )
                self.assertEqual(
                    client.post(
                        f"/services/{service_id}/status", data={"status": "active"}
                    ).status_code,
                    302,
                )
                self.assertEqual(
                    client.post(f"/services/{service_id}/delete").status_code, 302
                )

            with closing(sqlite3.connect(database)) as db:
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM customer_services").fetchone()[0],
                    0,
                )
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM service_renewals").fetchone()[0],
                    0,
                )

    def test_customer_service_json_import_is_idempotent(self):
        import import_customer_services

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            source = Path(tmp) / "services.json"
            app = load_app(database)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("upstream", "anytls://pw@example.com:443#demo"),
                )
                db.commit()
            source.write_text(
                json.dumps(
                    [
                        {
                            "account": "upstream",
                            "wechat_id": "customer",
                            "relationship": "借用",
                            "started_on": "2026-09-01",
                            "expires_on": "2027-09-01",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                import_customer_services.import_services(database, source), (1, 0)
            )
            self.assertEqual(
                import_customer_services.import_services(database, source), (0, 1)
            )
            with closing(sqlite3.connect(database)) as db:
                count, token_length = db.execute(
                    "SELECT COUNT(*), LENGTH(sub_token) FROM customer_services"
                ).fetchone()
            self.assertEqual((count, token_length), (1, 32))

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
                authenticate_session(app, client)

                response = client.post(f"/accounts/{account_id}/sync")

            self.assertEqual(response.status_code, 302)
            with closing(sqlite3.connect(database)) as db, db:
                protocol, raw_uri = db.execute("SELECT protocol, raw_uri FROM nodes").fetchone()
            self.assertEqual(protocol, "trojan")
            self.assertTrue(raw_uri.startswith("trojan://"))

    def test_public_subscribe_uses_branded_profile_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("customer@example.com", "anytls://pw@example.com:443#demo", "token"),
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
                    ("demo", 'bad\r\nInjected: yes"name'),
                )
                db.commit()

            with app.app.test_client() as client:
                response = client.get("/sub/token")

            self.assertEqual(response.status_code, 200)
            disposition = response.headers["Content-Disposition"]
            profile_title = response.headers["profile-title"]
            self.assertEqual(disposition, 'attachment; filename="SSRVPN.VIP"')
            self.assertEqual(profile_title, '"store-name=SSRVPN.VIP"')
            self.assertNotIn("customer@example.com", disposition + profile_title)
            self.assertNotIn("Injected", disposition + profile_title)

    def test_disabled_account_public_subscription_is_not_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token, status) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        "disabled-demo",
                        "anytls://pw@example.com:443#demo",
                        "disabled-token",
                        "disabled",
                    ),
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
                db.commit()

            with app.app.test_client() as client:
                response = client.get("/sub/disabled-token")

        self.assertEqual(response.status_code, 404)

    def test_public_subscribe_preserves_anytls_for_ssrvpn_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    (
                        "demo",
                        "anytls://pw@example.com:443?sni=sni.example.com#demo",
                        "token",
                    ),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "demo",
                        "example.com",
                        443,
                        "pw",
                        "anytls://pw@example.com:443?sni=sni.example.com#demo",
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
            self.assertEqual(response.headers["Cache-Control"], "no-store")
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

    def test_public_subscribe_never_fetches_upstream_when_local_nodes_are_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    ("demo", "https://slow.example/sub", "empty-token"),
                )
                db.commit()

            with mock.patch.object(
                app,
                "parse_subscribe_url",
                side_effect=AssertionError("public endpoint fetched upstream"),
            ) as parse:
                with app.app.test_client() as client:
                    response = client.get("/sub/empty-token")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["Retry-After"], "60")
        parse.assert_not_called()

    def test_public_subscribe_outputs_anytls_for_clash_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, sub_token) VALUES (?, ?, ?)",
                    (
                        "demo",
                        "anytls://pw@example.com:443?sni=sni.example.com&allowInsecure=1&fp=chrome#demo",
                        "token",
                    ),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "demo",
                        "example.com",
                        443,
                        "pw",
                        "anytls://pw@example.com:443?sni=sni.example.com&allowInsecure=1&fp=chrome#demo",
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
        self.assertEqual(proxies["vless-node"]["servername"], "vless-sni.example.com")
        self.assertTrue(proxies["vless-node"]["tls"])
        self.assertEqual(proxies["vless-node"]["flow"], "xtls-rprx-vision")
        self.assertEqual(proxies["hy2-node"]["sni"], "hy2-sni.example.com")
        self.assertTrue(proxies["hy2-node"]["skip-cert-verify"])

    def test_init_db_migrates_traffic_metadata_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            with closing(sqlite3.connect(database)) as db, db:
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
            app = load_app(database)
            with closing(sqlite3.connect(database)) as db, db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(accounts)")}
                tables = {row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
                migration_versions = [row[0] for row in db.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                )]
                admin_columns = {
                    row[1] for row in db.execute("PRAGMA table_info(admin_users)")
                }
                traffic_indexes = {
                    row[1] for row in db.execute("PRAGMA index_list(traffic_logs)")
                }

        self.assertTrue({
            "traffic_upload_bytes",
            "traffic_download_bytes",
            "expire_date",
            "last_traffic_reset_on",
        }.issubset(columns))
        self.assertIn("traffic_collectors", tables)
        self.assertIn("rate_limits", tables)
        self.assertIn("maintenance_state", tables)
        self.assertIn("customer_services", tables)
        self.assertIn("service_renewals", tables)
        self.assertIn("session_version", admin_columns)
        self.assertIn("idx_traffic_logs_recorded_at", traffic_indexes)
        self.assertEqual(
            migration_versions,
            list(range(1, app.SCHEMA_VERSION + 1)),
        )

    def test_database_path_rejects_empty_or_directory_values(self):
        original_mode = REPO_ROOT.stat().st_mode & 0o777
        for configured in ("", str(REPO_ROOT)):
            with self.subTest(configured=configured):
                spec = importlib.util.spec_from_file_location(
                    "anytls_panel_invalid_database",
                    APP_PATH,
                )
                module = importlib.util.module_from_spec(spec)
                with mock.patch.dict(
                    os.environ,
                    {"ANYTLS_DATABASE": configured},
                    clear=False,
                ):
                    with self.assertRaisesRegex(RuntimeError, "regular file|non-empty"):
                        spec.loader.exec_module(module)
        self.assertEqual(REPO_ROOT.stat().st_mode & 0o777, original_mode)

    def test_database_connections_enforce_foreign_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with app.app.app_context():
                enabled = app.get_db().execute("PRAGMA foreign_keys").fetchone()[0]

        self.assertEqual(enabled, 1)

    def test_database_connections_wait_for_short_write_contention(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with app.app.app_context():
                db = app.get_db()
                busy_timeout = db.execute("PRAGMA busy_timeout").fetchone()[0]
                journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]

        self.assertEqual(busy_timeout, 15000)
        self.assertEqual(journal_mode.lower(), "wal")

    def test_password_change_rejects_passwords_shorter_than_deploy_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "UPDATE admin_users SET password_hash=? WHERE username='admin'",
                    (app.hash_password("existing-password"),),
                )
                db.commit()

            with app.app.test_client() as client:
                authenticate_session(app, client)
                response = client.post(
                    "/settings/password",
                    data={
                        "old_password": "existing-password",
                        "new_password": "short7",
                        "confirm_password": "short7",
                    },
                )

            with closing(sqlite3.connect(database)) as db, db:
                stored_hash = db.execute(
                    "SELECT password_hash FROM admin_users WHERE username='admin'"
                ).fetchone()[0]

        self.assertEqual(response.status_code, 302)
        self.assertTrue(app.verify_password(stored_hash, "existing-password")[0])
        self.assertFalse(app.verify_password(stored_hash, "short7")[0])

    def test_traffic_log_retention_prunes_details_but_preserves_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) "
                    "VALUES ('demo', 'anytls://pw@example.com:443', 999)"
                ).lastrowid
                db.execute(
                    "INSERT INTO traffic_logs (account_id, bytes_used, recorded_at) "
                    "VALUES (?, 100, datetime('now', '-100 days'))",
                    (account_id,),
                )
                db.execute(
                    "INSERT INTO traffic_logs (account_id, bytes_used) VALUES (?, 200)",
                    (account_id,),
                )
                db.commit()
                deleted = app.prune_traffic_logs(db, force=True)
                rows = db.execute(
                    "SELECT bytes_used FROM traffic_logs ORDER BY id"
                ).fetchall()
                total = db.execute(
                    "SELECT traffic_used_bytes FROM accounts WHERE id=?",
                    (account_id,),
                ).fetchone()[0]

        self.assertEqual(deleted, 1)
        self.assertEqual([row[0] for row in rows], [200])
        self.assertEqual(total, 999)

    def test_account_sync_skips_account_deleted_during_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("deleted-during-sync", "https://sub.example/list"),
                ).lastrowid
                db.commit()

            def delete_then_return(_url):
                with closing(sqlite3.connect(database)) as other, other:
                    other.execute("PRAGMA foreign_keys=ON")
                    other.execute("DELETE FROM accounts WHERE id=?", (account_id,))
                    other.commit()
                return ([{
                    "name": "stale",
                    "host": "stale.example.com",
                    "port": 443,
                    "password": "pw",
                    "raw_uri": "anytls://pw@stale.example.com:443#stale",
                    "protocol": "anytls",
                }], {})

            with mock.patch.object(app, "parse_subscribe_url", side_effect=delete_then_return):
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post(f"/accounts/{account_id}/sync")

            with closing(sqlite3.connect(database)) as db, db:
                account_count = db.execute(
                    "SELECT COUNT(*) FROM accounts WHERE id=?", (account_id,)
                ).fetchone()[0]
                orphan_count = db.execute(
                    "SELECT COUNT(*) FROM nodes WHERE account_id=?", (account_id,)
                ).fetchone()[0]

        self.assertEqual(response.status_code, 302)
        self.assertEqual(account_count, 0)
        self.assertEqual(orphan_count, 0)

    def test_account_sync_keeps_existing_nodes_when_parser_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://invalid"),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "existing",
                        "existing.example.com",
                        443,
                        "pw",
                        "anytls://pw@existing.example.com:443#existing",
                    ),
                )
                db.commit()

            with mock.patch.object(app, "parse_subscribe_url", return_value=([], {})):
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post(f"/accounts/{account_id}/sync")

            with closing(sqlite3.connect(database)) as db, db:
                rows = db.execute(
                    "SELECT name FROM nodes WHERE account_id=?", (account_id,)
                ).fetchall()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(rows, [("existing",)])

    def test_sync_all_skips_account_deleted_during_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("deleted-during-sync-all", "https://sub.example/list"),
                ).lastrowid
                db.commit()

            def delete_then_return(_url):
                with closing(sqlite3.connect(database)) as other, other:
                    other.execute("PRAGMA foreign_keys=ON")
                    other.execute("DELETE FROM accounts WHERE id=?", (account_id,))
                    other.commit()
                return ([], {})

            with mock.patch.object(app, "parse_subscribe_url", side_effect=delete_then_return):
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post("/api/sync-all")

            with closing(sqlite3.connect(database)) as db, db:
                orphan_count = db.execute(
                    "SELECT COUNT(*) FROM nodes WHERE account_id=?", (account_id,)
                ).fetchone()[0]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["results"][0]["status"], "skipped")
        self.assertEqual(orphan_count, 0)

    def test_sync_all_keeps_existing_nodes_when_parser_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                account_id = db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("demo", "anytls://invalid"),
                ).lastrowid
                db.execute(
                    "INSERT INTO nodes (account_id, name, host, port, password, raw_uri) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        account_id,
                        "existing",
                        "existing.example.com",
                        443,
                        "pw",
                        "anytls://pw@existing.example.com:443#existing",
                    ),
                )
                db.commit()

            with mock.patch.object(app, "parse_subscribe_url", return_value=([], {})):
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post("/api/sync-all")

            with closing(sqlite3.connect(database)) as db, db:
                rows = db.execute(
                    "SELECT name FROM nodes WHERE account_id=?", (account_id,)
                ).fetchall()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["results"][0]["status"], "error")
        self.assertEqual(rows, [("existing",)])

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
                    "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) "
                    "VALUES (?, ?, ?)",
                    ("demo", "https://sub.example/list", 500),
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
                    authenticate_session(app, client)
                    response = client.post(f"/accounts/{account_id}/sync")

            with closing(sqlite3.connect(database)) as db, db:
                metadata = db.execute(
                    "SELECT traffic_used_bytes, traffic_upload_bytes, "
                    "traffic_download_bytes, traffic_limit_gb, expire_date "
                    "FROM accounts WHERE id=?",
                    (account_id,),
                ).fetchone()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(metadata, (500, 100, 200, 10, "2030-01-02"))

    def test_public_subscribe_does_not_convert_anytls_for_shadowrocket_clients(self):
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
                        "demo",
                        "example.com",
                        443,
                        "pw",
                        "anytls://pw@example.com:443#demo",
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
                authenticate_session(app, client)

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
                    authenticate_session(app, client)

                    response = client.post(f"/api/accounts/{account_id}/check-all")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["results"][0]["latency"], 123)
            with closing(sqlite3.connect(database)) as db, db:
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
                    authenticate_session(app, client)
                    response = client.post(f"/api/accounts/{account_id}/check-all")

        self.assertEqual(response.status_code, 200)
        self.assertGreater(max_active, 1)

    def test_check_all_nodes_rejects_oversized_batch_before_network_work(self):
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
                db.executemany(
                    "INSERT INTO nodes (account_id, name, host, port, password) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        (account_id, f"node-{index}", "example.com", 443, "pw")
                        for index in range(app.MAX_CHECK_NODES + 1)
                    ],
                )
                db.commit()

            with mock.patch.object(app, "_check_node_connect") as check:
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post(f"/api/accounts/{account_id}/check-all")

        self.assertEqual(response.status_code, 413)
        check.assert_not_called()

    def test_sync_all_fetches_subscriptions_concurrently(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                for index in range(4):
                    db.execute(
                        "INSERT INTO accounts (name, subscribe_url, traffic_used_bytes) "
                        "VALUES (?, ?, ?)",
                        (
                            f"account-{index}",
                            f"https://sub-{index}.example/list",
                            500,
                        ),
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
                }], {"used_bytes": 20})

            with mock.patch.object(app, "parse_subscribe_url", side_effect=slow_parse):
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post("/api/sync-all")
            with closing(sqlite3.connect(database)) as db, db:
                used_values = [
                    row[0]
                    for row in db.execute(
                        "SELECT traffic_used_bytes FROM accounts ORDER BY id"
                    )
                ]

        self.assertEqual(response.status_code, 200)
        self.assertGreater(max_active, 1)
        self.assertTrue(all(item["status"] == "ok" for item in response.get_json()["results"]))
        self.assertEqual(used_values, [500, 500, 500, 500])

    def test_sync_all_rejects_oversized_batch_before_network_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "anytls.db"
            app = load_app(database)
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.executemany(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    [
                        (f"account-{index}", f"https://sub-{index}.example/list")
                        for index in range(app.MAX_SYNC_ACCOUNTS + 1)
                    ],
                )
                db.commit()

            with mock.patch.object(app, "parse_subscribe_url") as parse:
                with app.app.test_client() as client:
                    authenticate_session(app, client)
                    response = client.post("/api/sync-all")

        self.assertEqual(response.status_code, 413)
        parse.assert_not_called()

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
                authenticate_session(app, client)
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
                authenticate_session(app, client)

                response = client.post(
                    "/api/check-by-host",
                    json={"host": "example.com", "port": 443.5},
                )

            self.assertEqual(response.status_code, 400)

    def test_node_probe_uses_address_family_agnostic_connection(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            raw_socket = mock.Mock()
            tls_socket = mock.Mock()
            tls_context = mock.Mock()
            tls_context.wrap_socket.return_value = tls_socket
            with mock.patch.dict(
                os.environ, {"ANYTLS_ALLOW_PRIVATE_NODE_PROBES": "1"}, clear=False
            ):
                with mock.patch.object(
                    app.socket, "create_connection", return_value=raw_socket
                ) as connect:
                    with mock.patch("ssl.create_default_context", return_value=tls_context):
                        result = app._check_node_connect("2001:db8::1", 443)

        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], ("2001:db8::1", 443))
        self.assertLessEqual(connect.call_args.kwargs["timeout"], 8)
        self.assertEqual(
            tls_context.minimum_version,
            app.ssl.TLSVersion.TLSv1_2,
        )
        tls_context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="2001:db8::1"
        )
        self.assertTrue(result["online"])

    def test_node_probe_rejects_private_targets_before_connecting(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            with mock.patch.object(
                app, "_resolve_subscription_addresses", return_value=["127.0.0.1"]
            ):
                with mock.patch.object(
                    app.socket,
                    "create_connection",
                    side_effect=AssertionError("private network called"),
                ) as connect:
                    result = app._check_node_connect("internal.example", 443)

        connect.assert_not_called()
        self.assertFalse(result["online"])
        self.assertIn("公网", result["msg"])

    def test_account_detail_template_escapes_js_arguments(self):
        content = (REPO_ROOT / "templates" / "account_detail.html").read_text(encoding="utf-8")

        self.assertIn('data-copy-value="{{ n.password | e }}"', content)
        self.assertIn('data-password="{{ n.password | e }}"', content)
        self.assertNotIn("onclick=", content)
        self.assertNotIn("value=\"' + data.url", content)
        self.assertIn("shareUrl.value = data.url", content)

    def test_dashboard_account_overview_shows_expiration_in_aligned_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = load_app(Path(tmp) / "anytls.db")
            app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
            with app.app.app_context():
                db = app.get_db()
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url, expire_date) VALUES (?, ?, ?)",
                    ("demo-account", "anytls://pw@example.com:443", "2030-01-02"),
                )
                db.execute(
                    "INSERT INTO accounts (name, subscribe_url) VALUES (?, ?)",
                    ("no-expiry", "anytls://pw2@example.com:443"),
                )
                db.commit()

            with app.app.test_client() as client:
                authenticate_session(app, client)
                response = client.get("/")

        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("<th>账号到期 / 流量重置</th>", html)
        account_name_index = html.index("<strong>demo-account</strong>")
        expiration_index = html.index("到期：2030-01-02")
        user_count_index = html.index('data-label="有效用户"', expiration_index)
        self.assertLess(account_name_index, expiration_index)
        self.assertLess(expiration_index, user_count_index)
        self.assertIn('data-label="账号到期 / 流量重置"', html)
        self.assertIn("每月 2 日重置", html)
        self.assertIn("账号到期：未设置", html)

    def test_monitor_template_does_not_embed_host_in_javascript(self):
        content = (REPO_ROOT / "templates" / "monitor.html").read_text(encoding="utf-8")

        self.assertIn('data-host="{{ n.host }}"', content)
        self.assertIn('data-action="check-host"', content)
        self.assertNotIn("checkOne('{{ n.host }}'", content)
        self.assertIn("row.querySelector('button[data-host][data-port]')", content)
        self.assertNotIn("hostPort.textContent.split(':')", content)

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

    def test_deploy_script_supports_interactive_credentials_and_automatic_https(self):
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
        self.assertIn("ANYTLS_PANEL_DOMAIN", content)
        self.assertIn("Panel administrator username", content)
        self.assertIn("Panel administrator password", content)
        self.assertIn("read -r -s -p", content)
        self.assertIn("administrator passwords do not match", content)
        self.assertNotIn("generate_password", content)
        self.assertIn("generate_api_token", content)
        self.assertIn("installing Caddy for automatic public ACME HTTPS", content)
        self.assertNotIn("https://acme-v02.api.letsencrypt.org/directory", content)
        self.assertIn("import anytls-panel.d/*.caddy", content)
        self.assertIn('systemctl enable caddy', content)
        self.assertIn('https://${PANEL_DOMAIN}/login', content)
        self.assertIn('systemctl restart "$SERVICE_NAME"', content)
        self.assertIn("prepare_release_source", content)
        self.assertIn("prepare_python_artifacts", content)
        self.assertIn("install_staged_release", content)
        self.assertIn("rollback_deployment", content)
        self.assertIn("deployment failed; restoring the previous release", content)
        self.assertIn("--require-hashes", content)
        self.assertIn("--no-index", content)
        self.assertIn("write_keepalive_config", content)
        self.assertIn("write_backup_config", content)
        self.assertIn("start_backups", content)
        self.assertIn('OnCalendar=*-*-* 03:15:00', content)
        self.assertIn('Restart=on-failure', content)
        self.assertIn('OnUnitActiveSec=1min', content)
        self.assertIn("sys.version_info >= (3, 12)", content)
        self.assertIn("Python 3.12 or newer is required", content)
        self.assertIn("mktemp -d /tmp/anytls-venv-check", content)
        self.assertIn('python3 -m venv "$probe_dir/venv"', content)
        self.assertIn('"$probe_dir/venv/bin/python" -m pip --version', content)
        self.assertIn("! -name data", content)
        self.assertIn('systemctl stop "$SERVICE_NAME"', content)
        self.assertIn("--no-install-recommends", content)
        self.assertIn("APT_UPDATED=0", content)
        self.assertNotIn("RPM_UPDATED=0", content)
        self.assertNotIn("dnf", content)
        self.assertNotIn("yum", content)
        self.assertIn('"systemctl:systemd"', content)
        self.assertIn("python_venv_packages", content)
        self.assertIn("python3-venv python3-pip", content)
        self.assertNotIn("python3-pip python3-virtualenv", content)
        self.assertIn("Ubuntu 24.04", content)
        self.assertNotIn("默认账号:", content)
        self.assertNotIn("默认密码:", content)

    def test_deploy_accepts_only_the_verified_ubuntu_release(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory() as tmp:
            os_release = Path(tmp) / "os-release"
            os_release.write_text(
                'ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8"
            )
            accepted = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; OS_RELEASE_FILE="$1"; validate_supported_os',
                    "deploy-os-check",
                    str(os_release),
                ],
                capture_output=True,
                text=True,
            )
            os_release.write_text(
                'ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8"
            )
            rejected = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; OS_RELEASE_FILE="$1"; validate_supported_os',
                    "deploy-os-check",
                    str(os_release),
                ],
                capture_output=True,
                text=True,
            )

        self.assertEqual(accepted.returncode, 0, msg=accepted.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("Ubuntu 24.04", rejected.stderr)

    def test_deploy_installs_caddy_from_verified_official_repository(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn("https://dl.cloudsmith.io/public/caddy/stable/gpg.key", content)
        self.assertIn("https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt", content)
        self.assertIn("65760C51EDEA2017CEA2CA15155B6D79CA56EA34", content)
        self.assertIn('CADDY_MIN_VERSION="2.11.4"', content)
        self.assertIn("dpkg --compare-versions", content)
        self.assertIn("installed Caddy is older than the verified minimum", content)

    def test_deploy_upgrades_existing_caddy_below_the_verified_minimum(self):
        script = REPO_ROOT / "deploy.sh"
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{script}"; '
                'UPGRADED=0; caddy() { :; }; systemctl() { return 0; }; '
                'dpkg() { [[ "$2" == "2.11.4" ]]; }; '
                'installed_caddy_version() { '
                '[[ "$UPGRADED" -eq 1 ]] && printf "2.11.4\\n" || '
                'printf "2.6.2\\n"; }; '
                'install_caddy_from_official_repository() { '
                'UPGRADED=1; printf "upgrade-called\\n"; }; '
                'ensure_caddy; printf "version=%s installed_now=%s '
                'attempted=%s\\n" "$(installed_caddy_version)" '
                '"$CADDY_INSTALLED_NOW" "$CADDY_INSTALL_ATTEMPTED"',
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("upgrade-called", result.stdout)
        self.assertIn("version=2.11.4 installed_now=0 attempted=1", result.stdout)

    def test_release_requires_main_head_and_successful_ci_for_exact_sha(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("actions: read", workflow)
        self.assertIn('tag_commit="$(git rev-parse "$GITHUB_SHA^{commit}")"', workflow)
        self.assertIn('[[ "$(git rev-parse origin/main)" == "$tag_commit" ]]', workflow)
        self.assertIn("actions/workflows/ci.yml/runs", workflow)
        self.assertIn("head_sha=$tag_commit", workflow)
        self.assertIn("event=push", workflow)
        self.assertIn("status=success", workflow)

    def test_release_manifest_includes_frontend_assets(self):
        manifest = {
            line.strip()
            for line in (REPO_ROOT / "release-files.txt").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        }
        required_assets = {
            "static/favicon.svg",
            "static/app.css",
            "static/vendor/LICENSE.bootstrap-icons",
            "static/vendor/bootstrap-icons.min.css",
            "static/vendor/fonts/bootstrap-icons.woff",
            "static/vendor/fonts/bootstrap-icons.woff2",
        }

        self.assertTrue(
            required_assets <= manifest,
            msg=f"release manifest is missing: {sorted(required_assets - manifest)}",
        )
        for asset in required_assets:
            with self.subTest(asset=asset):
                self.assertTrue((REPO_ROOT / asset).is_file())

    def test_deploy_stages_source_before_replacing_the_installed_directory(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp) / "panel"
            (panel_dir / "templates").mkdir(parents=True)
            for name in (
                "app.py",
                "database_maintenance.py",
                "db_migrations.py",
                "input_limits.py",
                "node_probe.py",
                "protocol_codecs.py",
                "security_utils.py",
                "sqlite_rate_limit.py",
                "traffic_token.py",
                "requirements.txt",
                "deploy.sh",
                "uninstall.sh",
            ):
                (panel_dir / name).write_text(f"proof-{name}\n", encoding="utf-8")
            (panel_dir / "templates" / "base.html").write_text(
                "proof-template\n", encoding="utf-8"
            )
            (panel_dir / "static").mkdir()
            (panel_dir / "static" / "favicon.svg").write_text(
                "proof-icon\n", encoding="utf-8"
            )
            (panel_dir / "static" / ".secret_key").write_text(
                "must-not-stage\n", encoding="utf-8"
            )
            (panel_dir / "static" / "debug.log").write_text(
                "must-not-stage\n", encoding="utf-8"
            )
            (panel_dir / "release-files.txt").write_text(
                "app.py\n"
                "database_maintenance.py\n"
                "db_migrations.py\n"
                "input_limits.py\n"
                "node_probe.py\n"
                "protocol_codecs.py\n"
                "security_utils.py\n"
                "sqlite_rate_limit.py\n"
                "traffic_token.py\n"
                "requirements.txt\n"
                "deploy.sh\n"
                "uninstall.sh\n"
                "templates/base.html\n"
                "static/favicon.svg\n"
                "release-files.txt\n",
                encoding="utf-8",
            )
            (panel_dir / ".secret_key").write_text(
                "must-not-stage\n", encoding="utf-8"
            )
            (panel_dir / ".DS_Store").write_text(
                "must-not-stage\n", encoding="utf-8"
            )
            (panel_dir / "untracked-junk").write_text(
                "must-not-stage\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env["TEST_PANEL_DIR"] = str(panel_dir)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; SERVICE_NAME="audit-panel"; '
                    'SCRIPT_DIR="$TEST_PANEL_DIR"; '
                    'validate_panel_dir() { :; }; validate_install_target() { :; }; '
                    'prepare_release_source; '
                    'test -f "$RELEASE_SOURCE/app.py"; '
                    'test "$(cat "$RELEASE_SOURCE/app.py")" = "proof-app.py"; '
                    'test ! -e "$RELEASE_SOURCE/.secret_key"; '
                    'test ! -e "$RELEASE_SOURCE/.DS_Store"; '
                    'test ! -e "$RELEASE_SOURCE/untracked-junk"; '
                    'test -f "$RELEASE_SOURCE/static/favicon.svg"; '
                    'test ! -e "$RELEASE_SOURCE/static/.secret_key"; '
                    'test ! -e "$RELEASE_SOURCE/static/debug.log"; '
                    'test -f "$PANEL_DIR/app.py"; printf STAGED_OK',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("STAGED_OK", result.stdout)

    def test_deploy_initializes_database_from_installed_release_directory(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp) / "panel"
            panel_dir.mkdir()
            env = os.environ.copy()
            env["TEST_PANEL_DIR"] = str(panel_dir)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'SERVICE_USER="audit"; ADMIN_USER=""; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'runuser() { printf "%s\\n" "$PWD"; }; '
                    'initialize_database',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], str(panel_dir))

    def test_release_manifest_cannot_traverse_a_symlinked_parent(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            source = root / "source"
            destination = root / "destination"
            outside = root / "outside"
            source.mkdir()
            destination.mkdir()
            outside.mkdir()
            (outside / "base.html").write_text("private\n", encoding="utf-8")
            (source / "templates").symlink_to(outside, target_is_directory=True)
            (source / "release-files.txt").write_text(
                "templates/base.html\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.update({
                "TEST_SOURCE": str(source),
                "TEST_DESTINATION": str(destination),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'copy_release_files "$TEST_SOURCE" "$TEST_DESTINATION"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not traverse symlinks", result.stderr)

    def test_deploy_smoke_database_uses_a_safe_copy_of_existing_data(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            data_dir = panel_dir / "data"
            smoke_database = root / "smoke" / "anytls.db"
            data_dir.mkdir(parents=True)
            smoke_database.parent.mkdir()
            with closing(sqlite3.connect(data_dir / "anytls.db")) as db, db:
                db.execute("CREATE TABLE proof (value TEXT)")
                db.execute("INSERT INTO proof VALUES ('existing-data')")
                db.commit()

            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_DATA_DIR": str(data_dir),
                "TEST_SMOKE_DATABASE": str(smoke_database),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$TEST_DATA_DIR"; '
                    'prepare_smoke_database "$TEST_SMOKE_DATABASE"; '
                    'python3 - "$TEST_SMOKE_DATABASE" <<\'PY\'\n'
                    'import sqlite3, sys\n'
                    'db = sqlite3.connect(sys.argv[1])\n'
                    'try:\n'
                    '    print(db.execute("SELECT value FROM proof").fetchone()[0])\n'
                    'finally:\n'
                    '    db.close()\n'
                    'PY',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "existing-data")

    def test_deploy_rollback_restores_previous_release_files(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            (panel_dir / "app.py").write_text("new-release\n", encoding="utf-8")
            (panel_dir / ".anytls-panel-install").write_text(
                "anytls-panel-managed-v1\n", encoding="utf-8"
            )
            (panel_dir / "data" / "anytls.db").write_text(
                "new-database\n", encoding="utf-8"
            )
            (panel_dir / "data" / ".secret_key").write_text(
                "new-secret\n", encoding="utf-8"
            )
            (rollback_dir / "code").mkdir(parents=True)
            (rollback_dir / "code" / "app.py").write_text(
                "old-release\n", encoding="utf-8"
            )
            (rollback_dir / "anytls.db").write_text(
                "old-database\n", encoding="utf-8"
            )
            (rollback_dir / "secret-key").write_text(
                "old-secret\n", encoding="utf-8"
            )
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'CODE_BACKED_UP=1; DATABASE_BACKED_UP=1; '
                    'DATABASE_STATE_CAPTURED=1; CONFIG_BACKED_UP=1; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "loaded\n"; return 0; }; '
                    'return 0; }; '
                    'rollback_deployment; '
                    'test ! -e "$PANEL_DIR/.anytls-panel-install"; '
                    'cat "$PANEL_DIR/app.py" "$DATA_DIR/anytls.db" '
                    '"$DATA_DIR/.secret_key"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            result.stdout.strip().splitlines()[-3:],
            ["old-release", "old-database", "old-secret"],
        )

    def test_deploy_rollback_restores_inactive_disabled_service_state(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            rollback_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
                "TEST_SYSTEMCTL_LOG": str(root / "systemctl.log"),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'SERVICE_USER="root"; SERVICE_GROUP="root"; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'CODE_BACKED_UP=0; DATABASE_STATE_CAPTURED=0; CONFIG_BACKED_UP=0; '
                    'OLD_PANEL_ACTIVE=0; OLD_PANEL_ENABLED=0; '
                    'OLD_CADDY_ACTIVE=0; OLD_CADDY_ENABLED=0; '
                    'OLD_HEALTH_TIMER_ACTIVE=0; OLD_HEALTH_TIMER_ENABLED=0; '
                    'OLD_PANEL_UNIT_PRESENT=1; OLD_CADDY_UNIT_PRESENT=1; '
                    'OLD_HEALTH_TIMER_UNIT_PRESENT=1; '
                    'OLD_PANEL_ENABLEMENT_MANAGED=1; '
                    'OLD_CADDY_ENABLEMENT_MANAGED=1; '
                    'OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=1; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "loaded\\n"; return 0; }; '
                    'printf "%s\\n" "$*" >> "$TEST_SYSTEMCTL_LOG"; return 0; }; '
                    'rollback_deployment; cat "$TEST_SYSTEMCTL_LOG"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        commands = result.stdout.splitlines()
        self.assertIn("disable audit-panel", commands)
        self.assertIn("disable caddy", commands)
        self.assertIn("disable audit-panel-healthcheck.timer", commands)
        self.assertIn("stop caddy", commands)

    def test_deploy_rollback_restores_active_enabled_service_state(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            rollback_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
                "TEST_SYSTEMCTL_LOG": str(root / "systemctl.log"),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'CODE_BACKED_UP=0; DATABASE_STATE_CAPTURED=0; CONFIG_BACKED_UP=0; '
                    'OLD_PANEL_ACTIVE=1; OLD_PANEL_ENABLED=1; '
                    'OLD_CADDY_ACTIVE=1; OLD_CADDY_ENABLED=1; '
                    'OLD_HEALTH_TIMER_ACTIVE=1; OLD_HEALTH_TIMER_ENABLED=1; '
                    'OLD_PANEL_UNIT_PRESENT=1; OLD_CADDY_UNIT_PRESENT=1; '
                    'OLD_HEALTH_TIMER_UNIT_PRESENT=1; '
                    'OLD_PANEL_ENABLEMENT_MANAGED=1; '
                    'OLD_CADDY_ENABLEMENT_MANAGED=1; '
                    'OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=1; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "loaded\n"; return 0; }; '
                    'printf "%s\n" "$*" >> "$TEST_SYSTEMCTL_LOG"; return 0; }; '
                    'rollback_deployment; cat "$TEST_SYSTEMCTL_LOG"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        commands = result.stdout.splitlines()
        self.assertIn("enable audit-panel", commands)
        self.assertIn("enable caddy", commands)
        self.assertIn("enable audit-panel-healthcheck.timer", commands)
        self.assertIn("start audit-panel", commands)
        self.assertIn("start caddy", commands)
        self.assertIn("start audit-panel-healthcheck.timer", commands)

    def test_deploy_failure_before_cutover_disables_new_caddy(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            env = os.environ.copy()
            env["TEST_SYSTEMCTL_LOG"] = str(root / "systemctl.log")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'DEPLOY_SUCCEEDED=0; CUTOVER_STARTED=0; ROLLBACK_FINISHED=0; '
                    'CADDY_INSTALL_ATTEMPTED=1; CADDY_INSTALLED_NOW=0; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "loaded\n"; return 0; }; '
                    'printf "%s\n" "$*" >> "$TEST_SYSTEMCTL_LOG"; return 0; }; '
                    'cleanup_deploy_artifacts; DEPLOY_SUCCEEDED=1; '
                    'cat "$TEST_SYSTEMCTL_LOG"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("stop caddy", result.stdout.splitlines())
        self.assertIn("disable caddy", result.stdout.splitlines())

    def test_fresh_install_rollback_ignores_units_that_remain_absent(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            rollback_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'CODE_BACKED_UP=0; DATABASE_STATE_CAPTURED=0; CONFIG_BACKED_UP=0; '
                    'OLD_PANEL_UNIT_PRESENT=0; OLD_CADDY_UNIT_PRESENT=1; '
                    'OLD_HEALTH_TIMER_UNIT_PRESENT=0; '
                    'OLD_PANEL_ACTIVE=0; OLD_PANEL_ENABLED=0; '
                    'OLD_CADDY_ACTIVE=0; OLD_CADDY_ENABLED=0; '
                    'OLD_HEALTH_TIMER_ACTIVE=0; OLD_HEALTH_TIMER_ENABLED=0; '
                    'OLD_PANEL_ENABLEMENT_MANAGED=1; '
                    'OLD_CADDY_ENABLEMENT_MANAGED=1; '
                    'OLD_HEALTH_TIMER_ENABLEMENT_MANAGED=1; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { '
                    'if [[ "$1" == "show" ]]; then '
                    'case "$2" in audit-panel|audit-panel-healthcheck.timer) '
                    'printf "not-found\n" ;; *) printf "loaded\n" ;; esac; '
                    'return 0; fi; return 0; }; '
                    'rollback_deployment; test "$ROLLBACK_FINISHED" -eq 1',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertNotIn("rollback incomplete", result.stderr)

    def test_deploy_rollback_reports_incomplete_restoration(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            rollback_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'SERVICE_USER="root"; SERVICE_GROUP="root"; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'CODE_BACKED_UP=0; DATABASE_STATE_CAPTURED=0; CONFIG_BACKED_UP=0; '
                    'OLD_PANEL_ACTIVE=0; OLD_PANEL_ENABLED=0; '
                    'OLD_CADDY_ACTIVE=0; OLD_CADDY_ENABLED=0; '
                    'OLD_HEALTH_TIMER_ACTIVE=0; OLD_HEALTH_TIMER_ENABLED=0; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "loaded\n"; return 0; }; '
                    '[[ "$*" != "daemon-reload" ]]; }; '
                    'if rollback_deployment; then exit 99; fi; '
                    'test "$ROLLBACK_FINISHED" -eq 0; printf ROLLBACK_FAILED',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, "ROLLBACK_FAILED")
        self.assertIn("rollback incomplete", result.stderr)

    def test_deploy_refuses_to_guess_when_systemd_state_cannot_be_read(self):
        script = REPO_ROOT / "deploy.sh"
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{script}"; systemctl() {{ return 1; }}; '
                'capture_systemd_unit_state audit-panel',
            ],
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot inspect systemd load state", result.stderr)

    def test_rollback_reports_systemd_probe_failure(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            (panel_dir / "data").mkdir(parents=True)
            rollback_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'CODE_BACKED_UP=0; DATABASE_STATE_CAPTURED=0; CONFIG_BACKED_UP=0; '
                    'OLD_PANEL_UNIT_PRESENT=0; OLD_CADDY_UNIT_PRESENT=0; '
                    'OLD_HEALTH_TIMER_UNIT_PRESENT=0; '
                    'CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'systemctl() { [[ "$1" == "show" ]] && return 1; return 0; }; '
                    'if rollback_deployment; then exit 99; fi; '
                    'test "$ROLLBACK_FINISHED" -eq 0',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("rollback could not inspect systemd unit", result.stderr)
        self.assertIn("rollback incomplete", result.stderr)

    def test_deploy_validates_and_normalizes_panel_domain(self):
        script = REPO_ROOT / "deploy.sh"
        for domain, expected in (
            ("panel.example.com", "panel.example.com"),
            ("VIP.SSRVPN.VIP.", "vip.ssrvpn.vip"),
            ("xn--fiqs8s.example", "xn--fiqs8s.example"),
        ):
            with self.subTest(domain=domain):
                env = os.environ.copy()
                env["TEST_DOMAIN"] = domain
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; PANEL_DOMAIN="$TEST_DOMAIN"; '
                        'validate_panel_domain; printf "%s" "$PANEL_DOMAIN"',
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(result.returncode, 0, msg=result.stderr)
                self.assertEqual(result.stdout, expected)

        for domain in (
            "localhost",
            "127.0.0.1",
            "https://panel.example.com",
            "bad_label.example.com",
            "-bad.example.com",
            "bad-.example.com",
        ):
            with self.subTest(domain=domain):
                env = os.environ.copy()
                env["TEST_DOMAIN"] = domain
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; PANEL_DOMAIN="$TEST_DOMAIN"; '
                        "validate_panel_domain",
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("panel domain", result.stderr)

    def test_deploy_install_copy_is_portable_to_bsd_cp(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            release_source = root / "release"
            panel_dir = root / "panel"
            release_source.mkdir()
            panel_dir.mkdir()
            (release_source / "app.py").write_text("portable-copy\n", encoding="utf-8")
            env = os.environ.copy()
            env.update({
                "TEST_RELEASE_SOURCE": str(release_source),
                "TEST_PANEL_DIR": str(panel_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'RELEASE_SOURCE="$TEST_RELEASE_SOURCE"; PANEL_DIR="$TEST_PANEL_DIR"; '
                    'copy_directory_contents "$RELEASE_SOURCE" "$PANEL_DIR"; '
                    'cat "$PANEL_DIR/app.py"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[0], "portable-copy")

    def test_deploy_accepts_noninteractive_initial_admin_credentials(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            env = os.environ.copy()
            env.update({
                "TEST_DATA_DIR": tmp,
                "ANYTLS_ADMIN_USER": "panel-admin",
                "ANYTLS_ADMIN_PASS": "strong-password",
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; DATA_DIR="$TEST_DATA_DIR"; '
                    "prepare_admin_credentials; "
                    'printf "%s|%s|%s" "$FRESH_DB" "$ADMIN_USER" "$ADMIN_PASS"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, "1|panel-admin|strong-password")

        for username, password, expected_error in (
            ("bad user", "strong-password", "administrator username"),
            ("panel-admin", "short", "administrator password"),
        ):
            with self.subTest(username=username, password=password):
                env = os.environ.copy()
                env.update({
                    "TEST_DATA_DIR": tmp,
                    "ANYTLS_ADMIN_USER": username,
                    "ANYTLS_ADMIN_PASS": password,
                })
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; DATA_DIR="$TEST_DATA_DIR"; '
                        "prepare_admin_credentials",
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, result.stderr)

    def test_account_traffic_token_cli_works_outside_project_directory(self):
        helper = REPO_ROOT / "traffic_token.py"
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / ".traffic_api_token"
            master_token = 'master-token-with-"quotes"-and-\\slashes'
            token_file.write_text(master_token + "\n", encoding="utf-8")
            env = os.environ.copy()
            env["ANYTLS_TRAFFIC_API_TOKEN_FILE"] = str(token_file)

            result = subprocess.run(
                [sys.executable, str(helper), "17"],
                cwd=tmp,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            signature = base64.urlsafe_b64encode(
                hmac.new(
                    master_token.encode(),
                    b"account:17",
                    hashlib.sha256,
                ).digest()
            ).decode().rstrip("=")
            self.assertEqual(result.stdout.strip(), f"atp1.17.{signature}")

    def test_deploy_rejects_dangerous_or_token_overlapping_directories(self):
        script = REPO_ROOT / "deploy.sh"
        for panel_dir in (
            "/",
            "/opt",
            "/var",
            "/opt/../root",
            "/var/lib",
            "/usr/local",
            "/home/jared",
            "/tmp/anytls-panel",
            "/private/tmp/anytls-panel",
        ):
            with self.subTest(panel_dir=panel_dir):
                env = os.environ.copy()
                env["ANYTLS_PANEL_DIR"] = panel_dir
                result = subprocess.run(
                    ["bash", "-c", f'source "{script}"; validate_panel_dir'],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ANYTLS_PANEL_DIR", result.stderr)

        env = os.environ.copy()
        env.update({
            "ANYTLS_PANEL_DIR": "/opt/anytls-panel-test",
            "ANYTLS_TRAFFIC_API_TOKEN_FILE": "/opt/anytls-panel-test/custom-token",
        })
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{script}"; validate_secret_paths',
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/etc/anytls-panel/<name>", result.stderr)

        env["ANYTLS_TRAFFIC_API_TOKEN_FILE"] = "/opt/anytls-panel-test"
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{script}"; validate_secret_paths',
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/etc/anytls-panel/<name>", result.stderr)

        for variable_name in (
            "ANYTLS_TRAFFIC_API_TOKEN_FILE",
            "ANYTLS_ADMIN_PASSWORD_FILE",
            "ANYTLS_SECRET_KEY_FILE",
        ):
            with self.subTest(variable_name=variable_name):
                env = os.environ.copy()
                env.update({
                    "ANYTLS_PANEL_DIR": "/opt/anytls-panel-test",
                    variable_name: "/tmp/attacker-controlled/secret",
                })
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; validate_secret_paths',
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(variable_name, result.stderr)

        env = os.environ.copy()
        env["ANYTLS_PANEL_DIR"] = "/opt/anytls-panel-test"
        result = subprocess.run(
            [
                "bash",
                "-c",
                f'source "{script}"; '
                "stat() { printf '0 755\\n'; }; validate_panel_dir",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            actual_parent = Path(tmp) / "actual"
            linked_parent = Path(tmp) / "linked"
            actual_parent.mkdir()
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            secret_path = linked_parent / "token"
            env = os.environ.copy()
            env["SECRET_PATH"] = str(secret_path)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'validate_secret_file_path "$SECRET_PATH" "$SECRET_PATH" TEST_SECRET',
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("parent must not be a symlink", result.stderr)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp) / "panel"
            panel_dir.mkdir()
            protected_target = Path(tmp) / "protected"
            protected_target.write_text("unchanged", encoding="utf-8")
            (panel_dir / ".anytls-panel-install").symlink_to(protected_target)
            env = os.environ.copy()
            env["TEST_PANEL_DIR"] = str(panel_dir)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; PANEL_DIR="$TEST_PANEL_DIR"; '
                    'validate_install_target',
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("untrusted installation marker", result.stderr)
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "unchanged")

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp) / "foreign-data"
            panel_dir.mkdir()
            (panel_dir / "important.txt").write_text("keep", encoding="utf-8")
            env = os.environ.copy()
            env["ANYTLS_PANEL_DIR"] = str(panel_dir)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; validate_install_target',
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-empty unmarked directory", result.stderr)
            self.assertTrue((panel_dir / "important.txt").is_file())

    def test_deploy_defaults_to_loopback_https_and_marks_managed_directory(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn('BIND_HOST="${ANYTLS_BIND_HOST:-127.0.0.1}"', content)
        self.assertIn(
            'SESSION_COOKIE_SECURE="${ANYTLS_SESSION_COOKIE_SECURE:-1}"',
            content,
        )
        self.assertIn('TRUST_PROXY="${ANYTLS_TRUST_PROXY:-1}"', content)
        self.assertIn("anytls-panel-managed-v1", content)
        self.assertIn('chown root:root "$PANEL_DIR/.anytls-panel-install"', content)
        self.assertIn("automatic HTTPS requires ANYTLS_BIND_HOST to remain on loopback", content)
        self.assertIn("certificate managed and renewed automatically by Caddy", content)

    def test_systemd_units_have_resource_and_kernel_hardening(self):
        required = (
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "ProtectHome=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectClock=true",
            "RestrictNamespaces=true",
            "LockPersonality=true",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "MemoryMax=256M",
            "TasksMax=64",
            "LimitNOFILE=4096",
        )
        for path in (REPO_ROOT / "deploy.sh", REPO_ROOT / "anytls-panel.service"):
            content = path.read_text(encoding="utf-8")
            for directive in required:
                self.assertIn(directive, content, msg=f"{directive} missing from {path.name}")

    def test_healthcheck_uses_readiness_hysteresis_and_certificate_warning(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn("/readyz", content)
        self.assertIn("FAILURE_THRESHOLD=3", content)
        self.assertIn("RECOVERY_COOLDOWN_SECONDS=300", content)
        self.assertIn("record_probe_failure", content)
        self.assertIn("reset_probe_failures", content)
        self.assertIn("health_recovery_suppressed", content)
        self.assertIn("openssl x509 -checkend 1814400", content)
        self.assertIn("certificate_expiring", content)

    def test_deploy_keeps_two_verified_backups_and_supports_delayed_rollback(self):
        content = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")

        self.assertIn("MAX_PERSISTENT_BACKUPS=2", content)
        self.assertIn("SHA256SUMS", content)
        self.assertIn("persist_rollback_backup", content)
        self.assertIn("delayed_rollback", content)
        self.assertIn("--rollback", content)

    def test_deploy_migrates_legacy_state_into_isolated_data_directory(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp)
            legacy_db = panel_dir / "anytls.db"
            with closing(sqlite3.connect(legacy_db)) as db, db:
                db.execute("CREATE TABLE proof (value TEXT NOT NULL)")
                db.execute("INSERT INTO proof (value) VALUES ('preserved')")
            (panel_dir / ".secret_key").write_text("legacy-secret", encoding="utf-8")
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_DATA_DIR": str(panel_dir / "data"),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; PANEL_DIR="$TEST_PANEL_DIR"; '
                    'DATA_DIR="$TEST_DATA_DIR"; '
                    'SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; '
                    'runuser() { shift 2; [[ "$1" == "--" ]] && shift; "$@"; }; '
                    'prepare_state_directory',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            with closing(sqlite3.connect(panel_dir / "data" / "anytls.db")) as db, db:
                preserved = db.execute("SELECT value FROM proof").fetchone()[0]
                integrity = db.execute("PRAGMA quick_check").fetchone()[0]
            self.assertEqual(preserved, "preserved")
            self.assertEqual(integrity, "ok")
            self.assertEqual(
                (panel_dir / "data" / ".secret_key").read_text(encoding="utf-8"),
                "legacy-secret",
            )
            self.assertTrue((panel_dir / ".anytls-panel-install").is_file())

    def test_legacy_database_rollback_does_not_leave_a_stale_data_copy(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            panel_dir.mkdir()
            rollback_dir.mkdir()
            with closing(sqlite3.connect(panel_dir / "anytls.db")) as db, db:
                db.execute("CREATE TABLE proof (value TEXT NOT NULL)")
                db.execute("INSERT INTO proof VALUES ('legacy-current')")
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'OLD_DATA_DATABASE_PRESENT=0; OLD_INSTALL_PRESENT=0; '
                    'CONFIG_BACKED_UP=0; CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'runuser() { shift 2; [[ "$1" == "--" ]] && shift; "$@"; }; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "not-found\n"; return 0; }; '
                    'return 0; }; '
                    'backup_database_for_rollback; prepare_state_directory; '
                    'backup_current_release; rollback_deployment; '
                    'test -f "$PANEL_DIR/anytls.db"; '
                    'test ! -e "$DATA_DIR/anytls.db"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            with closing(sqlite3.connect(panel_dir / "anytls.db")) as db, db:
                self.assertEqual(
                    db.execute("SELECT value FROM proof").fetchone()[0],
                    "legacy-current",
                )

    def test_legacy_database_is_removed_when_state_migration_fails_midway(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            panel_dir = root / "panel"
            rollback_dir = root / "rollback"
            panel_dir.mkdir()
            rollback_dir.mkdir()
            with closing(sqlite3.connect(panel_dir / "anytls.db")) as db, db:
                db.execute("CREATE TABLE proof (value TEXT NOT NULL)")
                db.execute("INSERT INTO proof VALUES ('legacy-current')")
            (panel_dir / ".secret_key").mkdir()
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_ROLLBACK_DIR": str(rollback_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; '
                    'PANEL_DIR="$TEST_PANEL_DIR"; DATA_DIR="$PANEL_DIR/data"; '
                    'ROLLBACK_DIR="$TEST_ROLLBACK_DIR"; SERVICE_NAME="audit-panel"; '
                    'SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; '
                    'SECRET_KEY_FILE="$DATA_DIR/.secret_key"; '
                    'TRAFFIC_API_TOKEN_FILE="$DATA_DIR/.traffic_api_token"; '
                    'ADMIN_PASSWORD_FILE="$DATA_DIR/.initial_admin_password"; '
                    'OLD_DATA_DATABASE_PRESENT=0; OLD_INSTALL_PRESENT=0; '
                    'CONFIG_BACKED_UP=0; CUTOVER_STARTED=1; ROLLBACK_FINISHED=0; '
                    'runuser() { shift 2; [[ "$1" == "--" ]] && shift; "$@"; }; '
                    'systemctl() { '
                    '[[ "$1" == "show" ]] && { printf "not-found\n"; return 0; }; '
                    'return 0; }; '
                    'backup_database_for_rollback; prepare_state_directory',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("legacy panel state file must be regular", result.stderr)
            self.assertTrue((panel_dir / "anytls.db").is_file())
            self.assertFalse((panel_dir / "data" / "anytls.db").exists())

    def test_ci_and_macos_gate_use_the_hashed_development_lock(self):
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        operations = (REPO_ROOT / "docs" / "OPERATIONS.md").read_text(
            encoding="utf-8"
        )
        dev_input = (REPO_ROOT / "requirements-dev.in").read_text(encoding="utf-8")

        self.assertIn("--require-hashes -r requirements-dev.txt", workflow)
        self.assertIn("python -m bandit -q -ll", workflow)
        self.assertNotIn("python -m pip install flake8 pip-audit", workflow)
        self.assertIn("python3.12 -m venv .venv", operations)
        self.assertIn("brew install python@3.12 shellcheck actionlint", operations)
        self.assertIn("--require-hashes -r requirements-dev.txt", operations)
        self.assertIn("git clone --depth 1 --branch v1.4.0", operations)
        self.assertIn("flake8==7.3.0", dev_input)
        self.assertIn("bandit==1.9.4", dev_input)
        self.assertIn("pip-audit==2.10.1", dev_input)
        self.assertIn("coverage==7.15.4", dev_input)
        self.assertIn("stevedore==5.9.1", dev_input)

    def test_deploy_rejects_symlinked_data_marker(self):
        script = REPO_ROOT / "deploy.sh"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            panel_dir = Path(tmp)
            data_dir = panel_dir / "data"
            data_dir.mkdir()
            protected_target = panel_dir / "protected"
            protected_target.write_text("unchanged", encoding="utf-8")
            (data_dir / ".anytls-panel-data").symlink_to(protected_target)
            env = os.environ.copy()
            env.update({
                "TEST_PANEL_DIR": str(panel_dir),
                "TEST_DATA_DIR": str(data_dir),
            })
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; PANEL_DIR="$TEST_PANEL_DIR"; '
                    'DATA_DIR="$TEST_DATA_DIR"; '
                    'SERVICE_USER="$(id -un)"; SERVICE_GROUP="$(id -gn)"; '
                    'prepare_state_directory',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("data marker must be a regular non-symlink", result.stderr)
            self.assertEqual(protected_target.read_text(encoding="utf-8"), "unchanged")

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
            self.assertIn("app:create_app()", content)
            self.assertNotIn("-w 2", content)
        self.assertIn('SERVICE_USER="${ANYTLS_SERVICE_USER:-anytls-panel}"', deploy)
        self.assertIn("service user must not be root", deploy)
        self.assertIn("User=anytls-panel", service)
        self.assertNotIn("User=root", deploy + service)
        self.assertIn("NoNewPrivileges=true", deploy)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertIn("ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS", deploy)
        self.assertIn("ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=0", service)
        self.assertIn("ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS=0", service)
        self.assertIn("ANYTLS_ALLOW_PRIVATE_NODE_PROBES=0", service)
        self.assertIn("ANYTLS_TRAFFIC_LOG_RETENTION_DAYS=90", service)
        self.assertIn("ANYTLS_MAX_REQUEST_BYTES=4194304", service)
        self.assertIn("ANYTLS_MAX_REQUEST_BYTES must be between", deploy)
        self.assertIn("--bind 127.0.0.1:8866", service)
        self.assertIn("ANYTLS_SESSION_COOKIE_SECURE=1", service)
        self.assertIn("ReadWritePaths=/opt/anytls-panel/data", service)
        self.assertIn("ReadWritePaths=${DATA_DIR}", deploy)
        self.assertIn('chown -R "root:$SERVICE_GROUP" "$PANEL_DIR"', deploy)
        self.assertNotIn('chown -R "$SERVICE_USER:$SERVICE_GROUP" "$PANEL_DIR"', deploy)
        self.assertIn('runuser -u "$SERVICE_USER" -- env', deploy)
        self.assertIn('HOST=${HOST:-127.0.0.1}', start)

    def test_uninstall_script_requires_explicit_confirmation(self):
        content = (REPO_ROOT / "uninstall.sh").read_text(encoding="utf-8")

        self.assertIn("--yes", content)
        self.assertIn("refusing to uninstall without --yes", content)
        self.assertIn("ANYTLS_SERVICE_NAME", content)
        self.assertIn("refusing to manage an unmarked directory", content)
        self.assertIn("/etc/caddy/anytls-panel.d/", content)
        self.assertIn("removing managed Caddy site", content)
        self.assertIn('"${SERVICE_NAME}-healthcheck.timer"', content)
        self.assertIn('"${SERVICE_NAME}-backup.timer"', content)
        self.assertIn('"$HEALTHCHECK_SCRIPT"', content)
        self.assertIn('"$CADDY_RESTART_DROPIN"', content)
        self.assertIn(
            "Uninstall service configuration but preserve the panel directory and database.",
            content,
        )
        self.assertNotIn("only disable the service", content)

    def test_release_defaults_and_workflow_use_immutable_signed_version(self):
        deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        workflow = REPO_ROOT / ".github" / "workflows" / "release.yml"

        self.assertIn('REPO_REF="${ANYTLS_REPO_REF:-v1.4.0}"', deploy)
        self.assertIn("AnyTLS_Panel/v1.4.0/deploy.sh", readme)
        self.assertTrue(workflow.is_file())
        workflow_text = workflow.read_text(encoding="utf-8")
        self.assertIn("id-token: write", workflow_text)
        validate_step = workflow_text.split(
            "- name: Validate release tag", 1
        )[1].split("- name:", 1)[0]
        self.assertIn("GH_TOKEN: ${{ github.token }}", validate_step)
        self.assertIn("cosign sign-blob", workflow_text)
        self.assertIn("--bundle", workflow_text)
        self.assertIn("--draft", workflow_text)
        self.assertIn("gh release upload", workflow_text)
        self.assertIn("--draft=false", workflow_text)

    def test_deploy_and_uninstall_reject_foreign_systemd_units(self):
        for script_name in ("deploy.sh", "uninstall.sh"):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as tmp:
                unit_dir = Path(tmp) / "systemd"
                unit_dir.mkdir()
                (unit_dir / "foreign.service").write_text(
                    "[Service]\n"
                    "WorkingDirectory=/opt/other-app\n"
                    "ExecStart=/opt/other-app/bin/server\n",
                    encoding="utf-8",
                )
                script = REPO_ROOT / script_name
                env = os.environ.copy()
                env["TEST_UNIT_DIR"] = str(unit_dir)
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; '
                        'PANEL_DIR=/opt/anytls-panel-test; '
                        'SERVICE_NAME=foreign; SYSTEMD_UNIT_DIR="$TEST_UNIT_DIR"; '
                        'validate_service_target; echo "service change allowed"',
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not belong", result.stderr)
                self.assertNotIn("service change allowed", result.stdout)

    def test_deploy_and_uninstall_reject_vendor_systemd_units(self):
        for script_name in ("deploy.sh", "uninstall.sh"):
            with self.subTest(script=script_name), tempfile.TemporaryDirectory() as tmp:
                script = REPO_ROOT / script_name
                env = os.environ.copy()
                env["TEST_UNIT_DIR"] = tmp
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f'source "{script}"; '
                        'systemctl() { printf "/usr/lib/systemd/system/ssh.service\\n"; }; '
                        'PANEL_DIR=/opt/anytls-panel-test; '
                        'SERVICE_NAME=ssh; SYSTEMD_UNIT_DIR="$TEST_UNIT_DIR"; '
                        'validate_service_target; echo "service change allowed"',
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("another systemd unit", result.stderr)
                self.assertNotIn("service change allowed", result.stdout)

    def test_uninstall_keep_data_still_requires_trusted_marker(self):
        script = REPO_ROOT / "uninstall.sh"
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["TEST_PANEL_DIR"] = tmp
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{script}"; PANEL_DIR="$TEST_PANEL_DIR"; '
                    'KEEP_DATA=1; validate_install_marker; echo "disabling service"',
                ],
                capture_output=True,
                text=True,
                env=env,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unmarked directory", result.stderr)
        self.assertNotIn("disabling service", result.stdout)

    def test_uninstall_rejects_dangerous_panel_directory_before_service_changes(self):
        script = REPO_ROOT / "uninstall.sh"
        for panel_dir in (
            "/",
            "/var/lib",
            "/usr/local",
            "/home/jared",
            "/tmp/anytls-panel",
        ):
            with self.subTest(panel_dir=panel_dir):
                env = os.environ.copy()
                env["ANYTLS_PANEL_DIR"] = panel_dir
                result = subprocess.run(
                    ["bash", str(script), "--yes"],
                    capture_output=True,
                    text=True,
                    env=env,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ANYTLS_PANEL_DIR", result.stderr)
                self.assertNotIn("disabling service", result.stdout)


if __name__ == "__main__":
    unittest.main()
