"""Regression checks for cycle alignment, URI credentials and probe fallbacks."""
import base64
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import quote

import yaml

from test_app import load_app, authenticate_session
from probe_fixtures import entry_result
import protocol_codecs
import proxy_verifier
import node_probe


class BugReview(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.panel = load_app(Path(self.temporary.name) / 'panel.db')
        self.panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.panel.app.test_client()
        authenticate_session(self.panel, self.client)

    def insert_account(self, count=1):
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute("""INSERT INTO accounts
                (name, subscribe_url, expire_date, last_traffic_reset_on, traffic_used_bytes)
                VALUES ('fixture', 'fixture-source', '2027-10-30', '2026-09-30', 300)""")
            for index in range(count):
                db.execute('''INSERT INTO nodes
                    (account_id, name, host, port, password, protocol, raw_uri)
                    VALUES (1, ?, 'fixture.example', 443, 'fixture', 'trojan', ?)''',
                    (f'fixture-{index}', f'trojan://fixture@fixture.example:443#fixture-{index}'))
            db.commit()

    def test_shadowsocks_base64_password_remains_literal(self):
        for password in ('fixture%41', 'fixture%25:密码', 'plain-fixture'):
            encoded = base64.urlsafe_b64encode(f'aes-256-gcm:{password}'.encode()).decode().rstrip('=')
            for credential in (encoded, 'aes-256-gcm:' + quote(password, safe='')):
                with self.subTest(password=password, credential=credential):
                    uri = f'ss://{credential}@fixture.example:443#fixture'
                    proxy = protocol_codecs.clash_proxy_from_uri(uri)
                    self.assertEqual(proxy['password'], password)
                    node = protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]
                    self.assertTrue(protocol_codecs.uri_preserves_clash_config(proxy, node['raw_uri']))

    def test_sync_new_reset_day_preserves_fresh_upstream_usage(self):
        self.insert_account()
        node = protocol_codecs.parse_protocol_uri('trojan://fixture@fixture.example:443#fixture', 'trojan')
        for endpoint in ('/accounts/1/sync', '/api/sync-all'):
            with self.subTest(endpoint=endpoint):
                self.assert_sync_cycle(endpoint, node)

    def assert_sync_cycle(self, endpoint, node):
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute("UPDATE accounts SET expire_date='2027-10-30', last_traffic_reset_on='2026-09-30'")
            db.commit()
        with mock.patch.object(self.panel, '_business_today', return_value=date(2026, 10, 1)), \
                mock.patch.object(self.panel, 'parse_subscribe_url', return_value=([node], {
                    'used_bytes': 12345, 'upload_bytes': 123, 'download_bytes': 12222,
                    'expire_date': '2027-11-01'})):
            response = self.client.post(endpoint)
            self.assertIn(response.status_code, (200, 302))
            self.client.get('/accounts/1')
            with self.panel.app.app_context():
                row = self.panel.get_db().execute('SELECT * FROM accounts WHERE id=1').fetchone()
                self.assertEqual((row['traffic_used_bytes'], row['traffic_upload_bytes'], row['traffic_download_bytes']),
                                 (12345, 123, 12222))
                self.assertEqual(row['last_traffic_reset_on'], '2026-10-01')
                self.panel.apply_due_traffic_resets(self.panel.get_db(), today=date(2026, 11, 1))
                self.assertEqual(self.panel.get_db().execute('SELECT traffic_used_bytes FROM accounts').fetchone()[0], 0)

    def test_sync_without_usage_preserves_local_cycle_marker(self):
        self.insert_account()
        with mock.patch.object(self.panel, '_business_today', return_value=date(2026, 10, 1)), \
                self.panel.app.app_context():
            db = self.panel.get_db()
            account = db.execute('SELECT * FROM accounts WHERE id=1').fetchone()
            nodes = self.panel._parse_subscription_content('trojan://fixture@fixture.example:443')
            self.panel._store_synced_account(db, account, nodes, {})
            db.commit()
            row = db.execute('SELECT * FROM accounts WHERE id=1').fetchone()
            self.assertEqual(row['last_traffic_reset_on'], '2026-09-30')
            self.assertEqual(row['traffic_used_bytes'], 300)

    def test_proxy_probe_reaches_working_second_public_address(self):
        node = protocol_codecs.parse_protocol_uri('trojan://fixture@fixture.example:443?sni=tls.fixture.example#fixture', 'trojan')
        reachable = '8.8.4.4'
        socket_calls = []
        core_calls = []
        sock = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = sock

        def connect(endpoint, timeout):
            socket_calls.append(endpoint[0])
            if endpoint[0] != reachable:
                raise ConnectionRefusedError
            return sock

        def core(proxy, directory, deadline):
            core_calls.append(proxy['server'])
            self.assertEqual(proxy['sni'], 'tls.fixture.example')
            self.assertFalse(proxy['skip-cert-verify'])
            if proxy['server'] != reachable:
                raise proxy_verifier.ProxyAccessFailed
            return 25

        with mock.patch.object(node_probe.socket, 'create_connection', side_effect=connect), \
                mock.patch.object(node_probe.ssl, 'create_default_context', return_value=context), \
                mock.patch.object(proxy_verifier, 'run_core', side_effect=core):
            result = proxy_verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8', reachable], self.temporary.name)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(socket_calls, ['8.8.8.8', reachable])
        self.assertEqual(core_calls, ['8.8.8.8', reachable])

    def test_address_fallback_shares_deadline_and_preserves_core_errors(self):
        clock = [100.0]
        deadlines = []

        def fail(proxy, directory, deadline):
            deadlines.append(deadline)
            clock[0] = deadline - 0.1
            raise proxy_verifier.ProxyAccessFailed

        with mock.patch.object(proxy_verifier.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(proxy_verifier, 'run_core', side_effect=fail):
            with self.assertRaises(proxy_verifier.ProxyAccessFailed):
                proxy_verifier._run_core_addresses({}, ['8.8.8.8', '8.8.4.4'], self.temporary.name, 108)
        self.assertEqual(deadlines, [104, 108])
        with mock.patch.object(proxy_verifier.time, 'monotonic', return_value=100), \
                mock.patch.object(proxy_verifier, 'run_core', side_effect=RuntimeError) as core:
            with self.assertRaises(RuntimeError):
                proxy_verifier._run_core_addresses({}, ['8.8.8.8', '8.8.4.4'], self.temporary.name, 108)
            self.assertEqual(core.call_count, 1)
        with mock.patch.object(proxy_verifier.time, 'monotonic', return_value=108), \
                mock.patch.object(proxy_verifier, 'run_core') as core:
            with self.assertRaises(TimeoutError):
                proxy_verifier._run_core_addresses({}, ['8.8.8.8'], self.temporary.name, 108)
            core.assert_not_called()

    def test_repeat_batch_checks_reach_remaining_nodes(self):
        self.insert_account(count=32)
        seen = []
        clock = [100.0]
        timeouts = []

        def probe(node, timeout=8):
            seen.append(node['id'])
            timeouts.append(timeout)
            return entry_result()

        def wave(function, items, max_workers=8):
            start = len(timeouts)
            result = [function(item) for item in items]
            clock[0] += max(timeouts[start:], default=0)
            return result

        with mock.patch.object(self.panel.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(self.panel, '_run_probe', side_effect=probe), \
                mock.patch.object(self.panel, '_bounded_parallel_map', side_effect=wave):
            first = self.client.post('/api/accounts/1/check-all').json
            second = self.client.post('/api/accounts/1/check-all').json
        self.assertEqual(first['incomplete'], 8)
        self.assertEqual(second['incomplete'], 8)
        self.assertEqual(len(set(seen)), 32)


if __name__ == '__main__':
    unittest.main(verbosity=2)
