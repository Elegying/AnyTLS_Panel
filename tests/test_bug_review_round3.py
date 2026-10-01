"""Regression checks for full address fallback and pasted subscription metadata."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import node_probe
from test_app import authenticate_session, load_app
from probe_fixtures import entry_result


class ReviewRoundThree(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.panel = load_app(Path(temporary.name) / 'panel.db')
        self.panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.panel.app.test_client()
        authenticate_session(self.panel, self.client)

    def test_entry_tls_failure_falls_back_without_relaxing_certificate_checks(self):
        for failure in (node_probe.ssl.SSLError('fixture certificate'), TimeoutError()):
            with self.subTest(failure=type(failure).__name__):
                sockets = [mock.Mock(), mock.Mock()]
                context = mock.Mock()
                context.wrap_socket.side_effect = [failure, sockets[1]]
                node = dict(protocol='trojan', host='fixture.example',
                            raw_uri='trojan://fixture@fixture.example:443?sni=tls.fixture.example')
                with mock.patch.object(node_probe.socket, 'create_connection', side_effect=sockets), \
                        mock.patch.object(node_probe.ssl, 'create_default_context', return_value=context):
                    result = node_probe.check_node_connect('fixture.example', 443, 8,
                                                          lambda *_: ['8.8.8.8', '8.8.4.4'], node=node)
                self.assertEqual(result['status'], 'entry')
                self.assertEqual(result['stages']['tls']['state'], 'success')
                self.assertEqual(result['tls_mode'], 'strict')
                self.assertEqual(context.wrap_socket.call_count, 2)
                for call in context.wrap_socket.call_args_list:
                    self.assertEqual(call.kwargs['server_hostname'], 'tls.fixture.example')
                self.assertNotEqual(context.verify_mode, node_probe.ssl.CERT_NONE)
                for sock in sockets:
                    sock.close.assert_called_once()

    def test_later_tcp_failure_preserves_completed_tls_failure_evidence(self):
        sock = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.side_effect = node_probe.ssl.SSLError('fixture certificate')
        with mock.patch.object(node_probe.socket, 'create_connection', side_effect=[sock, ConnectionRefusedError()]), \
                mock.patch.object(node_probe.ssl, 'create_default_context', return_value=context):
            result = node_probe.check_node_connect('fixture.example', 443, 8,
                                                  lambda *_: ['8.8.8.8', '8.8.4.4'],
                                                  node={'protocol': 'trojan', 'host': 'fixture.example'})
        self.assertEqual(result['status'], 'tls_error')
        self.assertEqual(result['stages']['tcp']['state'], 'success')
        self.assertEqual(result['stages']['tls']['state'], 'failed')

    def test_tls_timeout_leaves_time_for_next_address_in_both_network_paths(self):
        for path in ('subscription', 'entry'):
            with self.subTest(path=path):
                clock = [0.0]
                sockets = [mock.Mock(), mock.Mock()]
                timeouts = {}
                for index, sock in enumerate(sockets):
                    sock.settimeout.side_effect = lambda value, index=index: timeouts.update({index: value})
                context = mock.Mock()

                def wrap(sock, **kwargs):
                    if sock is sockets[0]:
                        clock[0] += timeouts[0]
                        raise TimeoutError()
                    return sock

                context.wrap_socket.side_effect = wrap
                connection, response = mock.Mock(), mock.Mock(status=200)
                response.getheader.return_value = ''
                response.read1.side_effect = [b'fixture', b'']
                connection.getresponse.return_value = response
                with mock.patch.object(node_probe.time, 'monotonic', side_effect=lambda: clock[0]), \
                        mock.patch.object(node_probe.socket, 'create_connection', side_effect=sockets) as connect, \
                        mock.patch.object(node_probe.ssl, 'create_default_context', return_value=context), \
                        mock.patch.object(self.panel, '_resolve_subscription_addresses', return_value=['8.8.8.8', '8.8.4.4']), \
                        mock.patch.object(self.panel.http.client, 'HTTPConnection', return_value=connection):
                    if path == 'subscription':
                        raw, redirect = self.panel._read_pinned_subscription_response('https://fixture.example/sub', 'fixture', deadline=8)
                        self.assertEqual((raw, redirect), (b'fixture', None))
                    else:
                        result = node_probe.check_node_connect('fixture.example', 443, 8,
                                                              lambda *_: ['8.8.8.8', '8.8.4.4'],
                                                              node={'protocol': 'trojan', 'host': 'fixture.example'})
                        self.assertEqual(result['status'], 'entry')
                self.assertEqual(connect.call_count, 2)
                self.assertEqual(clock[0], 4)

    def test_pasted_plain_and_base64_statistics_survive_import_and_sync(self):
        plain = '  STATUS=↑:1KB,↓:2KB,TOT:4GB Expires:2027-10-15\nanytls://fixture@fixture.example:443#fixture'
        for source in (plain, base64.b64encode(plain.encode()).decode()):
            with self.subTest(encoded=source != plain):
                nodes, info = self.panel.parse_subscribe_url(source)
                self.assertEqual(len(nodes), 1)
                self.assertEqual(info['used_bytes'], 3072)
                self.assertEqual(info['total_gb'], 4)
                self.assertEqual(info['expire_date'], '2027-10-15')
                response = self.client.post('/accounts/add', data={'subscribe_url': source})
                self.assertEqual(response.status_code, 302)
                account_id = int(response.location.rsplit('/', 1)[1])
                with self.panel.app.app_context():
                    db = self.panel.get_db()
                    row = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
                    self.assertEqual((row['traffic_used_bytes'], row['traffic_limit_gb'], row['expire_date']),
                                     (3072, 4, '2027-10-15'))
                    db.execute('UPDATE accounts SET traffic_used_bytes=0 WHERE id=?', (account_id,))
                    db.commit()
                self.client.post(f'/accounts/{account_id}/sync')
                with self.panel.app.app_context():
                    self.assertEqual(self.panel.get_db().execute('SELECT traffic_used_bytes FROM accounts WHERE id=?',
                                                                (account_id,)).fetchone()[0], 3072)

    def test_pasted_statistics_reject_combined_counter_overflow(self):
        source = 'STATUS=↑:4194304TB,↓:4194304TB,TOT:4GB\nanytls://fixture@fixture.example:443'
        _, info = self.panel.parse_subscribe_url(source)
        self.assertEqual(info['total_gb'], 4)
        self.assertFalse({'upload_bytes', 'download_bytes', 'used_bytes'} & info.keys())

    def test_subscription_body_timeout_also_preserves_fallback_budget(self):
        clock = [0.0]
        sockets = [mock.Mock(), mock.Mock()]
        connections = [mock.Mock(), mock.Mock()]
        responses = [mock.Mock(status=200), mock.Mock(status=200)]
        socket_timeout = [0.0]
        sockets[0].settimeout.side_effect = lambda value: socket_timeout.__setitem__(0, value)

        def stall(_size):
            clock[0] += socket_timeout[0]
            raise TimeoutError()

        responses[0].read1.side_effect = stall
        responses[1].read1.side_effect = [b'fixture', b'']
        for connection, response in zip(connections, responses):
            response.getheader.return_value = ''
            connection.getresponse.return_value = response
        with mock.patch.object(self.panel.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(self.panel, '_resolve_subscription_addresses', return_value=['8.8.8.8', '8.8.4.4']), \
                mock.patch.object(self.panel.socket, 'create_connection', side_effect=sockets), \
                mock.patch.object(self.panel.ssl, 'create_default_context') as context, \
                mock.patch.object(self.panel.http.client, 'HTTPConnection', side_effect=connections):
            context.return_value.wrap_socket.side_effect = lambda sock, **_: sock
            body, redirect = self.panel._read_pinned_subscription_response('https://fixture.example/sub', 'fixture', deadline=8)
        self.assertEqual((body, redirect), (b'fixture', None))
        self.assertEqual(clock[0], 4)
        for connection in connections:
            connection.close.assert_called_once()

    def test_vmess_display_rename_retains_health_but_credentials_clear_it(self):
        payload = {'v': '2', 'ps': 'original', 'add': 'fixture.example', 'port': '443',
                   'id': 'fixture-uuid', 'net': 'tcp', 'tls': 'tls'}

        def nodes():
            uri = 'vmess://' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return self.panel._parse_subscription_content(uri)

        with self.panel.app.app_context():
            db = self.panel.get_db()
            account_id = db.execute("INSERT INTO accounts(name, subscribe_url) VALUES ('fixture', 'fixture')").lastrowid
            self.panel._replace_account_nodes(db, account_id, nodes())
            evidence = json.dumps(entry_result())
            db.execute('UPDATE nodes SET probe_result=?, is_online=1', (evidence,))
            payload['ps'] = 'renamed'
            self.panel._replace_account_nodes(db, account_id, nodes())
            row = db.execute('SELECT * FROM nodes').fetchone()
            self.assertEqual(row['name'], 'renamed')
            self.assertEqual(row['probe_result'], evidence)
            for field, value in (('id', 'changed-uuid'), ('tls', ''), ('net', 'ws')):
                with self.subTest(field=field):
                    db.execute('UPDATE nodes SET probe_result=?, is_online=1', (evidence,))
                    payload[field] = value
                    self.panel._replace_account_nodes(db, account_id, nodes())
                    row = db.execute('SELECT * FROM nodes').fetchone()
                    self.assertEqual((row['is_online'], row['probe_result']), (-1, ''))
