"""Regression checks for the second sequential five-round audit."""
from pathlib import Path
from contextlib import closing
import hashlib
import http.client
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlparse

from test_app import authenticate_session, load_app
from probe_fixtures import entry_result
import node_monitor


class SecondFiveRoundAudit(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_round_one_collector_validates_decimal_port_and_updates_rule_names(self):
        script = Path(__file__).resolve().parent.parent / 'traffic_collector.sh'
        for port, valid in [('000443', True), ('08', True), ('65535', True),
                            ('0', False), ('65536', False),
                            (str(2**64 + 443), False), ('1+1', False)]:
            with self.subTest(port=port):
                command = f'''source "{script}"
current_euid() {{ printf 0; }}
command_is_available() {{ return 0; }}
PANEL_URL=https://panel.example
API_TOKEN=synthetic
ACCOUNT_ID=1
ANYTLS_PORT="$1"
validate_configuration || exit $?
printf '%s %s %s' "$ANYTLS_PORT" "$INPUT_RULE_COMMENT" "$OUTPUT_RULE_COMMENT"
'''
                result = subprocess.run(['bash', '-c', command, 'fixture', port],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                if valid:
                    expected = str(int(port))
                    self.assertEqual(result.stdout,
                                     f'{expected} anytls-panel-traffic-in-{expected} anytls-panel-traffic-out-{expected}')

    def test_round_two_scheduled_monitor_counts_tls_failures(self):
        panel = load_app(self.root / 'panel.db')
        with panel.app.app_context():
            db = panel.get_db()
            db.execute("INSERT INTO accounts(name, subscribe_url) VALUES ('fixture', 'fixture')")
            db.execute("""INSERT INTO nodes(account_id, name, host, port, password, raw_uri)
                       VALUES (1, 'fixture', 'node.example', 443, 'synthetic',
                               'anytls://synthetic@node.example:443')""")
            db.commit()
        result = entry_result()
        result.update(status='tls_error', online=False, msg='模拟证书错误')
        result['stages']['tls'] = {'state': 'failed', 'detail': '模拟证书错误'}
        with mock.patch.object(panel, '_run_probe', return_value=result):
            report = node_monitor.check_due_nodes(panel)
        self.assertEqual(report, {'checked': 1, 'verified': 0, 'failed': 1, 'incomplete': 0})
        with panel.app.app_context():
            health = panel._nodes_with_health(panel.get_db().execute('SELECT * FROM nodes').fetchall())[0]['health']
            self.assertEqual(health['status'], 'tls_error')

    def test_round_three_concurrent_password_update_cannot_be_overwritten(self):
        for endpoint in ('/settings/password', '/login'):
            with self.subTest(endpoint=endpoint):
                database = self.root / ('change.db' if endpoint == '/settings/password' else 'login.db')
                panel = load_app(database)
                panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
                client = panel.app.test_client()
                legacy_hash = hashlib.sha256(b'existing-password').hexdigest()
                concurrent_hash = panel.hash_password('concurrent-password')
                requested_hash = panel.hash_password('requested-password')
                with panel.app.app_context():
                    db = panel.get_db()
                    db.execute('UPDATE admin_users SET password_hash=?', (legacy_hash,))
                    db.commit()
                if endpoint == '/settings/password':
                    authenticate_session(panel, client)

                def concurrent_change(_password):
                    with closing(sqlite3.connect(database)) as db, db:
                        db.execute('UPDATE admin_users SET password_hash=?, session_version=session_version+1',
                                   (concurrent_hash,))
                    return requested_hash

                values = ({'old_password': 'existing-password', 'new_password': 'requested-password',
                           'confirm_password': 'requested-password'} if endpoint == '/settings/password'
                          else {'username': 'admin', 'password': 'existing-password'})
                with mock.patch.object(panel, 'hash_password', side_effect=concurrent_change):
                    response = client.post(endpoint, data=values)
                self.assertIn(response.status_code, (200, 302))
                with panel.app.app_context():
                    user = panel.get_db().execute('SELECT * FROM admin_users').fetchone()
                    self.assertEqual(user['password_hash'], concurrent_hash)
                    self.assertEqual(user['session_version'], 2)
                with client.session_transaction() as session:
                    self.assertFalse(session.get('logged_in', False))

    def test_round_three_legacy_login_upgrade_still_works(self):
        panel = load_app(self.root / 'legacy.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        legacy_hash = hashlib.sha256(b'existing-password').hexdigest()
        with panel.app.app_context():
            db = panel.get_db()
            db.execute('UPDATE admin_users SET password_hash=?', (legacy_hash,))
            db.commit()
        client = panel.app.test_client()
        self.assertEqual(client.post('/login', data={
            'username': 'admin', 'password': 'existing-password'}).status_code, 302)
        self.assertEqual(client.get('/').status_code, 200)
        with panel.app.app_context():
            user = panel.get_db().execute('SELECT * FROM admin_users').fetchone()
            self.assertNotEqual(user['password_hash'], legacy_hash)
            self.assertTrue(panel.verify_password(user['password_hash'], 'existing-password')[0])
            self.assertEqual(user['session_version'], 1)

    def test_round_four_explicit_zero_port_is_rejected_before_dns(self):
        panel = load_app(self.root / 'port.db')
        for url in ('https://node.example:0/sub', 'https://node.example:65536/sub'):
            with self.subTest(url=url):
                with mock.patch.object(panel, '_resolve_subscription_addresses') as resolver:
                    with self.assertRaises(ValueError):
                        panel._resolve_public_subscription_url(url)
                    resolver.assert_not_called()
        for suffix, expected in (('', 443), (':443', 443), (':8443', 8443)):
            with mock.patch.object(panel, '_resolve_subscription_addresses', return_value=['8.8.8.8']) as resolver:
                _, addresses = panel._resolve_public_subscription_url(f'https://node.example{suffix}/sub')
                self.assertEqual(addresses, ['8.8.8.8'])
                self.assertEqual(resolver.call_args.args[1], expected)

    def test_round_five_subscription_host_header_supports_international_domains(self):
        panel = load_app(self.root / 'idn.db')
        for url, expected in (
            ('https://例子.测试:8443/sub', 'xn--fsqu00a.xn--0zwm56d:8443'),
            ('https://bücher.example/sub', 'xn--bcher-kva.example'),
            ('https://node.example/sub', 'node.example'),
            ('https://[2001:4860:4860::8888]:8443/sub', '[2001:4860:4860::8888]:8443'),
        ):
            with self.subTest(url=url):
                host = panel._subscription_host_header(urlparse(url))
                self.assertEqual(host, expected)
                connection = http.client.HTTPConnection('fixture.example')
                sock = mock.Mock()
                connection.sock = sock
                try:
                    connection.putrequest('GET', '/sub', skip_host=True)
                    connection.putheader('Host', host)
                    connection.endheaders()
                    self.assertIn(b'Host: ' + expected.encode('ascii') + b'\r\n',
                                  sock.sendall.call_args.args[0])
                finally:
                    connection.close()
