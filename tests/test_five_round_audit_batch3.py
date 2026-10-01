"""Regression checks for the third sequential five-round audit."""
from pathlib import Path
from contextlib import closing
import sqlite3
import http.client
import io
import time
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlparse

import node_probe
from test_app import authenticate_session, load_app


class ThirdFiveRoundAudit(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_round_one_tcp_latency_excludes_failed_address_wait(self):
        clock = [0.0]
        sock = mock.Mock()

        def connect(address, timeout):
            if address[0] == '8.8.8.8':
                clock[0] += timeout
                raise TimeoutError()
            clock[0] += 0.125
            return sock

        with mock.patch.object(node_probe.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(node_probe.socket, 'create_connection', side_effect=connect):
            result = node_probe.check_node_connect(
                'fixture.example', 443, 8, lambda *_: ['8.8.8.8', '8.8.4.4'],
                node={'protocol': 'vless', 'host': 'fixture.example'})
        self.assertEqual(result['status'], 'entry')
        self.assertEqual(result['latency'], 125)
        self.assertEqual(clock[0], 4.125)
        sock.close.assert_called_once()

    def test_round_two_service_account_status_is_locked_until_save(self):
        for endpoint in ('/services/add', '/services/1/edit'):
            with self.subTest(endpoint=endpoint):
                database = self.root / ('add.db' if endpoint.endswith('add') else 'edit.db')
                panel = load_app(database)
                panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
                client = panel.app.test_client()
                authenticate_session(panel, client)
                with panel.app.app_context():
                    db = panel.get_db()
                    db.executemany('INSERT INTO accounts(name, subscribe_url) VALUES (?, ?)',
                                   [('original', 'fixture'), ('target', 'fixture')])
                    if endpoint.endswith('edit'):
                        db.execute("""INSERT INTO customer_services
                                   (account_id, wechat_id, started_on, expires_on, sub_token)
                                   VALUES (1, 'fixture', '2026-01-01', '2027-01-01', 'fixture-token')""")
                    db.commit()
                original_get_db = panel.get_db
                blocked = []

                def checked_db():
                    db = original_get_db()
                    proxy = mock.Mock(wraps=db)

                    def execute(sql, parameters=()):
                        cursor = db.execute(sql, parameters)
                        if sql.startswith('SELECT status FROM accounts'):
                            row = cursor.fetchone()
                            with closing(sqlite3.connect(database, timeout=0)) as writer:
                                try:
                                    writer.execute("UPDATE accounts SET status='disabled' WHERE id=2")
                                    writer.commit()
                                except sqlite3.OperationalError:
                                    blocked.append(True)
                                else:
                                    blocked.append(False)
                            return mock.Mock(fetchone=mock.Mock(return_value=row))
                        return cursor

                    proxy.execute.side_effect = execute
                    return proxy

                with mock.patch.object(panel, 'get_db', side_effect=checked_db):
                    response = client.post(endpoint, headers={'X-Panel-Form': '1'}, data={
                        'account_id': 2, 'wechat_id': 'fixture', 'started_on': '2026-01-01',
                        'expires_on': '2027-01-01'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(blocked, [True])
                with panel.app.app_context():
                    db = panel.get_db()
                    self.assertEqual(db.execute('SELECT account_id FROM customer_services').fetchone()[0], 2)
                    self.assertEqual(db.execute('SELECT status FROM accounts WHERE id=2').fetchone()[0], 'active')

    def test_round_three_truncated_http_body_is_not_accepted_as_subscription(self):
        panel = load_app(self.root / 'truncated.db')
        payload = b'anytls://synthetic@node.example:443#fixture'
        for advertised in (len(payload), len(payload) + 100):
            with self.subTest(advertised=advertised):
                raw = (f'HTTP/1.1 200 OK\r\nContent-Length: {advertised}\r\n\r\n'.encode()
                       + payload)
                sock = mock.Mock()
                sock.makefile.return_value = io.BytesIO(raw)
                response = http.client.HTTPResponse(sock)
                response.begin()
                try:
                    if advertised == len(payload):
                        self.assertEqual(panel._read_subscription_body(
                            response, sock, time.monotonic() + 5), payload)
                    else:
                        with self.assertRaises(http.client.IncompleteRead):
                            panel._read_subscription_body(response, sock, time.monotonic() + 5)
                finally:
                    response.close()

    def test_round_three_interrupted_sync_preserves_existing_nodes(self):
        panel = load_app(self.root / 'sync.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        client = panel.app.test_client()
        authenticate_session(panel, client)
        with panel.app.app_context():
            db = panel.get_db()
            db.execute("INSERT INTO accounts(name, subscribe_url, node_count) VALUES ('fixture', 'https://node.example/sub', 1)")
            db.execute("""INSERT INTO nodes(account_id, name, host, port, password, raw_uri)
                       VALUES (1, 'saved', 'saved.example', 443, 'synthetic',
                               'anytls://synthetic@saved.example:443#saved')""")
            db.commit()

        def interrupted_read(*_args, **_kwargs):
            sock = mock.Mock()
            sock.makefile.return_value = io.BytesIO(
                b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n'
                b'anytls://synthetic@replacement.example:443#replacement')
            response = http.client.HTTPResponse(sock)
            response.begin()
            try:
                return panel._read_subscription_body(response, sock, time.monotonic() + 5)
            finally:
                response.close()

        with mock.patch.object(panel, '_read_subscription_url', side_effect=interrupted_read):
            self.assertEqual(client.post('/accounts/1/sync').status_code, 302)
        with panel.app.app_context():
            db = panel.get_db()
            self.assertEqual(db.execute('SELECT name FROM nodes').fetchone()[0], 'saved')
            self.assertEqual(db.execute('SELECT node_count FROM accounts').fetchone()[0], 1)

    def test_round_four_unicode_request_target_is_encoded_without_changing_tokens(self):
        panel = load_app(self.root / 'unicode-path.db')
        cases = [
            ('https://node.example/订阅/节点?token=a+b%2Fc&label=中文',
             '/%E8%AE%A2%E9%98%85/%E8%8A%82%E7%82%B9?token=a+b%2Fc&label=%E4%B8%AD%E6%96%87'),
            ('https://node.example/sub%2Fpath?token=a%2Bb&x=1+2', '/sub%2Fpath?token=a%2Bb&x=1+2'),
            ('https://node.example/sub;v=1?token=a', '/sub;v=1?token=a'),
            ('https://node.example', '/'),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                target = panel._subscription_request_target(urlparse(url))
                self.assertEqual(target, expected)
                connection = http.client.HTTPConnection('fixture.example')
                sock = mock.Mock()
                connection.sock = sock
                try:
                    connection.putrequest('GET', target)
                    connection.endheaders()
                    self.assertTrue(sock.sendall.call_args.args[0].startswith(
                        b'GET ' + expected.encode('ascii') + b' HTTP/1.1\r\n'))
                finally:
                    connection.close()

    def test_round_five_real_http_parser_falls_back_after_truncation(self):
        panel = load_app(self.root / 'fallback.db')
        payload = b'anytls://synthetic@node.example:443#complete'
        sockets = [mock.Mock(), mock.Mock()]
        sockets[0].makefile.return_value = io.BytesIO(
            b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n' + payload)
        sockets[1].makefile.return_value = io.BytesIO(
            f'HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n'.encode() + payload)
        with mock.patch.object(panel, '_resolve_subscription_addresses', return_value=['8.8.8.8', '8.8.4.4']), \
                mock.patch.object(panel.socket, 'create_connection', side_effect=sockets) as connect, \
                mock.patch.object(panel.ssl, 'create_default_context') as context:
            context.return_value.wrap_socket.side_effect = lambda sock, **_kwargs: sock
            body, redirect = panel._read_pinned_subscription_response(
                'https://例子.测试/订阅?token=a%2Bb', 'fixture')
        self.assertEqual(body, payload)
        self.assertIsNone(redirect)
        self.assertEqual([call.args[0][0] for call in connect.call_args_list], ['8.8.8.8', '8.8.4.4'])
        for sock in sockets:
            request = sock.sendall.call_args.args[0]
            self.assertIn(b'GET /%E8%AE%A2%E9%98%85?token=a%2Bb HTTP/1.1\r\n', request)
            self.assertIn(b'Host: xn--fsqu00a.xn--0zwm56d\r\n', request)
            self.assertTrue(sock.close.called)

    def test_round_five_import_and_sync_reject_names_invalidated_by_existing_rules(self):
        for endpoint in ('/accounts/add', '/accounts/1/sync', '/api/sync-all'):
            with self.subTest(endpoint=endpoint):
                database = self.root / (endpoint.replace('/', '_') + '.db')
                panel = load_app(database)
                panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
                client = panel.app.test_client()
                authenticate_session(panel, client)
                uri = 'anytls://synthetic@new.example:443#aaa'
                with panel.app.app_context():
                    db = panel.get_db()
                    db.execute('INSERT INTO accounts(name, subscribe_url, node_count) VALUES (?, ?, 1)',
                               ('fixture', uri))
                    db.execute("""INSERT INTO nodes(account_id, name, host, port, password, raw_uri)
                               VALUES (1, 'a', 'saved.example', 443, 'synthetic',
                                       'anytls://synthetic@saved.example:443#a')""")
                    db.execute("INSERT INTO rename_rules(old_text, new_text) VALUES ('a', ?)", ('a' * 200,))
                    db.commit()
                response = client.post(endpoint, headers={'X-Panel-Form': '1'}, data={
                    'name': 'incoming', 'subscribe_url': uri, 'traffic_limit_gb': '250'})
                if endpoint == '/accounts/add':
                    self.assertEqual(response.status_code, 422)
                elif endpoint == '/api/sync-all':
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json['results'][0]['status'], 'error')
                else:
                    self.assertEqual(response.status_code, 302)
                with panel.app.app_context():
                    db = panel.get_db()
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0], 1)
                    self.assertEqual(db.execute('SELECT name FROM nodes').fetchone()[0], 'a')
                    self.assertEqual(db.execute('SELECT node_count FROM accounts').fetchone()[0], 1)
                    self.assertIsNone(db.execute('SELECT last_synced_at FROM accounts').fetchone()[0])
