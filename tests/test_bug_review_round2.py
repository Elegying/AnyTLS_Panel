"""Regression checks for imports, rename deletion and subscription statistics."""
import json
import math
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_app import load_app, authenticate_session
from import_customer_services import import_services
import node_probe


class ReviewRoundTwo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'panel.db'
        self.panel = load_app(self.database)
        self.panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.panel.app.test_client()
        authenticate_session(self.panel, self.client)

    def account(self, name='fixture', node_name='fixture'):
        with self.panel.app.app_context():
            db = self.panel.get_db()
            account_id = db.execute('INSERT INTO accounts(name, subscribe_url, sub_token) VALUES (?, ?, ?)',
                                    (name, 'https://fixture.example/sub', 'fixture-token-' + str(db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]))).lastrowid
            nodes = self.panel._parse_subscription_content('trojan://fixture@fixture.example:443#' + node_name)
            self.panel._replace_account_nodes(db, account_id, nodes)
            db.commit()
        return account_id

    def test_deleting_rule_must_not_break_valid_public_subscription(self):
        self.account(node_name='A' * 40)
        for old, new in [('A', 'B'), ('A', 'A' * 20)]:
            response = self.client.post('/settings/rename-rules/add', data={'old_text': old, 'new_text': new})
            self.assertEqual(response.status_code, 302)
        before = self.client.get('/sub/fixture-token-0').status_code
        deletion = self.client.post('/settings/rename-rules/1/delete')
        after = self.client.get('/sub/fixture-token-0').status_code
        self.assertEqual(before, 200)
        self.assertEqual(deletion.status_code, 302)
        self.assertEqual(after, 200)
        with self.panel.app.app_context():
            self.assertEqual(self.panel.get_db().execute('SELECT COUNT(*) FROM rename_rules').fetchone()[0], 2)

    def test_import_must_reject_ambiguous_account_name(self):
        self.account(name='duplicate')
        self.account(name='duplicate')
        source = Path(self.temp.name) / 'services.json'
        source.write_text(json.dumps([{'account': 'duplicate', 'wechat_id': 'fixture-customer',
                                     'started_on': '2026-10-01', 'expires_on': '2027-10-01'}]))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            import_services(self.database, source)
        with self.panel.app.app_context():
            self.assertEqual(self.panel.get_db().execute('SELECT COUNT(*) FROM customer_services').fetchone()[0], 0)

    def test_import_shares_web_limits_and_rolls_back_invalid_batches(self):
        self.account()
        self.account(name='unrelated-duplicate')
        self.account(name='unrelated-duplicate')
        source = Path(self.temp.name) / 'services.json'
        row = {'account': 'fixture', 'wechat_id': 'w' * 200, 'notes': 'n' * 4000,
               'started_on': '2026-10-01', 'expires_on': '2027-10-01'}
        source.write_text(json.dumps([row]))
        self.assertEqual(import_services(self.database, source), (1, 0))
        with self.panel.app.app_context():
            token = self.panel.get_db().execute('SELECT sub_token FROM customer_services').fetchone()[0]
        row['expires_on'] = '2028-10-01'
        for invalid in (dict(row, wechat_id='w' * 201), dict(row, notes='n' * 4001),
                        dict(row, wechat_id=None), dict(row, expires_on='invalid'), None):
            with self.subTest(invalid=type(invalid).__name__):
                source.write_text(json.dumps([row, invalid]))
                with self.assertRaises(ValueError):
                    import_services(self.database, source)
                with self.panel.app.app_context():
                    service = self.panel.get_db().execute('SELECT * FROM customer_services').fetchone()
                    self.assertEqual(service['expires_on'], '2027-10-01')
                    self.assertEqual(service['sub_token'], token)
        source.write_text(json.dumps([row]))
        self.assertEqual(import_services(self.database, source), (0, 1))

    def test_invalid_legacy_rules_can_be_removed_progressively(self):
        self.account()
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.executemany('INSERT INTO rename_rules(old_text, new_text) VALUES (?, ?)', [('', 'x'), ('', 'y')])
            db.commit()
        for rule_id in (1, 2):
            self.assertEqual(self.client.post(f'/settings/rename-rules/{rule_id}/delete').status_code, 302)
            with self.panel.app.app_context():
                self.assertEqual(self.panel.get_db().execute('SELECT COUNT(*) FROM rename_rules').fetchone()[0], 2 - rule_id)
        self.assertEqual(self.client.get('/sub/fixture-token-0').status_code, 200)

    def test_sync_must_not_persist_nonfinite_upstream_quota(self):
        self.account()
        raw = ('STATUS=TOT:' + '9' * 400 + 'GB\ntrojan://fixture@fixture.example:443#fixture').encode()
        with mock.patch.object(self.panel, '_read_subscription_url', return_value=(raw, '')):
            response = self.client.post('/accounts/1/sync')
        self.assertEqual(response.status_code, 302)
        with self.panel.app.app_context():
            quota = self.panel.get_db().execute('SELECT traffic_limit_gb FROM accounts').fetchone()[0]
        api_response = self.client.get('/api/accounts')
        def reject_nonfinite(value):
            raise ValueError(value)
        try:
            json.loads(api_response.data, parse_constant=reject_nonfinite)
            strict_json_ok = True
        except ValueError:
            strict_json_ok = False
        self.assertTrue(math.isfinite(quota))
        self.assertEqual(quota, 250)
        self.assertTrue(strict_json_ok)

    def test_invalid_status_fields_do_not_override_valid_metadata(self):
        invalid = self.panel._parse_status_line('STATUS=↑:1.2.3GB,↓:2KB,TOT:' + '9' * 400 + 'GB Expires:2027-02-30')
        self.assertEqual(invalid['download_bytes'], 2048)
        for key in ('upload_bytes', 'total_gb', 'expire_date', 'used_bytes'):
            self.assertNotIn(key, invalid)
        raw = ('STATUS=TOT:' + '9' * 400 + 'GB Expires:2027-02-30\nanytls://fixture@fixture.example:443').encode()
        with mock.patch.object(self.panel, '_read_subscription_url', return_value=(raw, 'upload=1024; download=1024; total=8192')):
            _, info = self.panel.parse_subscribe_url('https://fixture.example/sub')
        self.assertEqual(info['total_gb'], 8192 / 1024**3)
        self.assertEqual(info['used_bytes'], 2048)

    def test_partial_body_statistics_recompute_total_after_header_merge(self):
        raw = b'STATUS=\xe2\x86\x93:2KB\nanytls://fixture@fixture.example:443'
        with mock.patch.object(self.panel, '_read_subscription_url', return_value=(raw, 'upload=1024; download=1024')):
            _, info = self.panel.parse_subscribe_url('https://fixture.example/sub')
        self.assertEqual((info['upload_bytes'], info['download_bytes'], info['used_bytes']), (1024, 2048, 3072))
        with mock.patch.object(self.panel, '_read_subscription_url', return_value=(raw, f'upload={2**63-1}; download=0')):
            _, info = self.panel.parse_subscribe_url('https://fixture.example/sub')
        self.assertFalse({'upload_bytes', 'download_bytes', 'used_bytes'} & info.keys())

    def test_new_account_preserves_zero_upstream_quota(self):
        node = self.panel._parse_subscription_content('anytls://fixture@fixture.example:443')[0]
        with mock.patch.object(self.panel, 'parse_subscribe_url', return_value=([node], {'total_gb': 0})):
            response = self.client.post('/accounts/add', data={'name': 'fixture', 'subscribe_url': 'fixture'})
        self.assertEqual(response.status_code, 302)
        with self.panel.app.app_context():
            self.assertEqual(self.panel.get_db().execute('SELECT traffic_limit_gb FROM accounts').fetchone()[0], 0)

    def test_zero_quota_displays_consistently_without_false_warning(self):
        self.account()
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute('UPDATE accounts SET traffic_limit_gb=0, traffic_used_bytes=?', (250 * 1024**3,))
            db.commit()
        self.assertIn('0% / 0.0 GB', self.client.get('/accounts/1').text)
        self.assertNotIn('100.0%', self.client.get('/accounts').text)
        with mock.patch.object(self.panel, 'render_template', wraps=self.panel.render_template) as render:
            self.assertEqual(self.client.get('/').status_code, 200)
            self.assertEqual(render.call_args.kwargs['warning_accounts'], [])
        self.assertNotIn('100.0%', self.client.get('/').text)

    def test_subscription_connect_timeout_leaves_budget_for_next_address(self):
        clock, attempts = [0.0], []
        sock, connection, response = mock.Mock(), mock.Mock(), mock.Mock(status=200)
        response.getheader.return_value = ''
        response.read1.side_effect = [b'fixture-body', b'']
        connection.getresponse.return_value = response

        def connect(endpoint, timeout):
            attempts.append((endpoint[0], timeout))
            if endpoint[0] == '8.8.8.8':
                clock[0] += timeout
                raise TimeoutError
            return sock

        with mock.patch.object(self.panel.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(self.panel, '_resolve_subscription_addresses', return_value=['8.8.8.8', '8.8.4.4']), \
                mock.patch.object(self.panel.socket, 'create_connection', side_effect=connect), \
                mock.patch.object(self.panel.ssl, 'create_default_context') as context, \
                mock.patch.object(self.panel.http.client, 'HTTPConnection', return_value=connection):
            context.return_value.wrap_socket.return_value = sock
            body, redirect = self.panel._read_pinned_subscription_response('https://fixture.example/sub', 'fixture', deadline=10)
        self.assertEqual(body, b'fixture-body')
        self.assertIsNone(redirect)
        self.assertEqual(attempts, [('8.8.8.8', 5), ('8.8.4.4', 5)])
        context.return_value.wrap_socket.assert_called_once_with(sock, server_hostname='fixture.example')

    def test_entry_probe_connect_timeout_leaves_budget_for_next_address(self):
        clock, attempts = [0.0], []
        sock = mock.Mock()
        node = dict(protocol='trojan', host='fixture.example', port=443,
                    raw_uri='trojan://fixture@fixture.example:443')

        def connect(endpoint, timeout):
            attempts.append((endpoint[0], timeout))
            if endpoint[0] == '8.8.8.8':
                clock[0] += timeout
                raise TimeoutError
            return sock

        with mock.patch.object(node_probe.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(node_probe.socket, 'create_connection', side_effect=connect), \
                mock.patch.object(node_probe.ssl, 'create_default_context') as context:
            context.return_value.wrap_socket.return_value = sock
            result = node_probe.check_node_connect('fixture.example', 443, 8,
                                                  lambda *_: ['8.8.8.8', '8.8.4.4'], node=node)
        self.assertEqual(result['status'], 'entry')
        self.assertEqual(attempts, [('8.8.8.8', 4), ('8.8.4.4', 4)])

    def test_service_detail_must_apply_due_monthly_reset(self):
        self.account()
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute("UPDATE accounts SET expire_date='2027-11-01', last_traffic_reset_on='2026-09-01', traffic_used_bytes=12345")
            db.execute("""INSERT INTO customer_services
                (account_id, wechat_id, started_on, expires_on, sub_token)
                VALUES (1, 'fixture-customer', '2026-01-01', '2027-01-01', 'fixture-service-token')""")
            db.commit()
        for endpoint in ('/services/1', '/api/accounts'):
            with self.subTest(endpoint=endpoint), \
                    mock.patch.object(self.panel, '_business_today', return_value=date(2026, 10, 1)):
                with self.panel.app.app_context():
                    db = self.panel.get_db()
                    db.execute("UPDATE accounts SET last_traffic_reset_on='2026-09-01', traffic_used_bytes=12345")
                    db.commit()
                self.assertEqual(self.client.get(endpoint).status_code, 200)
                with self.panel.app.app_context():
                    self.assertEqual(self.panel.get_db().execute('SELECT traffic_used_bytes FROM accounts').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
