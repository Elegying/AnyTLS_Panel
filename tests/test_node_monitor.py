import json
import os
import socket
import shutil
import subprocess
import threading
import ssl
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from test_app import load_app, authenticate_session, extract_csrf_token
from probe_fixtures import entry_result
import node_probe as probe


class LayeredProbeTests(unittest.TestCase):
    def run_probe(self, protocol='trojan', query='', resolver=None):
        return probe.check_node_connect('entry.example', 443, 1,
            resolver or (lambda *_: ['8.8.8.8']), node={
                'protocol': protocol, 'host': 'entry.example',
                'raw_uri': f'{protocol}://fake@entry.example:443?{query}'})

    def test_tls_failure_keeps_tcp_fact_and_no_proxy_success(self):
        with mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()), \
             mock.patch.object(probe.ssl, 'create_default_context') as context:
            context.return_value.wrap_socket.side_effect = ssl.SSLError('private-credential')
            result = self.run_probe()
        self.assertFalse(result['online'])
        self.assertEqual(result['status'], 'tls_error')
        self.assertEqual(result['stages']['tcp']['state'], 'success')
        self.assertEqual(result['stages']['tls']['state'], 'failed')
        self.assertEqual(result['stages']['auth']['state'], 'not_run')
        self.assertNotIn('private-credential', json.dumps(result))

    def test_sni_alpn_and_verification_mode(self):
        for insecure in (False, True):
            context = ssl.create_default_context()
            with mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()) as connect, \
                 mock.patch.object(probe.ssl, 'create_default_context', return_value=context), \
                 mock.patch.object(context, 'wrap_socket', return_value=mock.Mock()) as wrap, \
                 mock.patch.object(context, 'set_alpn_protocols') as alpn:
                r = self.run_probe(query='sni=tls.example&type=grpc&allowInsecure=' + ('1' if insecure else '0'))
            self.assertEqual(connect.call_args.args[0], ('8.8.8.8', 443))
            self.assertEqual(wrap.call_args.kwargs['server_hostname'], 'tls.example')
            alpn.assert_called_once_with(['h2'])
            self.assertEqual(context.verify_mode, ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED)
            self.assertEqual(context.check_hostname, not insecure)
            self.assertEqual(r['tls_mode'], 'insecure_configured' if insecure else 'strict')
            self.assertEqual(r['status'], 'entry')
            self.assertNotEqual(r['stages']['access']['state'], 'success')
            if insecure:
                self.assertIn('证书有效性未验证', r['stages']['tls']['detail'])

    def test_dns_refused_timeout_and_tls_timeout_are_distinct(self):
        r = self.run_probe(resolver=mock.Mock(side_effect=ValueError('dns')))
        self.assertEqual(r['stages']['dns']['state'], 'failed')
        self.assertEqual(r['stages']['tcp']['state'], 'not_run')
        for error, reason in ((ConnectionRefusedError(), '拒绝'), (TimeoutError(), '超时'), (OSError(), '失败')):
            with mock.patch.object(probe.socket, 'create_connection', side_effect=error):
                r = self.run_probe()
            self.assertEqual(r['stages']['dns']['state'], 'success')
            self.assertEqual(r['stages']['tcp']['state'], 'failed')
            self.assertIn(reason, r['msg'])
        with mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()), \
             mock.patch.object(probe.ssl, 'create_default_context') as context:
            context.return_value.wrap_socket.side_effect = socket.timeout()
            r = self.run_probe()
        self.assertEqual(r['status'], 'tls_error')
        self.assertEqual(r['stages']['tcp']['state'], 'success')

    def test_private_mixed_dns_and_rebinding_remain_blocked(self):
        with mock.patch.object(probe.socket, 'create_connection') as connect:
            for addresses in (['127.0.0.1'], ['8.8.8.8', '10.0.0.1'], ['::1'], ['198.18.0.1']):
                r = self.run_probe(resolver=lambda *_, a=addresses: a)
                self.assertFalse(r['online'])
            connect.assert_not_called()
        resolver = mock.Mock(side_effect=[['8.8.8.8'], ['127.0.0.1']])
        with mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()) as connect:
            self.run_probe(protocol='vless', resolver=resolver)
        resolver.assert_called_once()
        self.assertEqual(connect.call_args.args[0][0], '8.8.8.8')

    def test_protocol_applicability_and_no_credential_output(self):
        with mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()) as connect, \
             mock.patch.object(probe.ssl, 'create_default_context') as tls:
            quic = self.run_probe('hysteria2')
            connect.assert_not_called()
            self.assertEqual(quic['status'], 'unsupported')
            self.assertEqual(quic['stages']['tcp']['state'], 'not_applicable')
            plain = self.run_probe('vless')
            self.assertEqual(plain['stages']['tls']['state'], 'not_applicable')
            reality = self.run_probe('vless', 'security=reality&sni=example.com')
            self.assertEqual(reality['stages']['tls']['state'], 'unsupported')
            fingerprint = self.run_probe('trojan', 'fp=chrome')
            self.assertEqual(fingerprint['stages']['tls']['state'], 'unsupported')
            tls.assert_not_called()
            self.assertNotIn('fake@', json.dumps([plain, reality, quic]))

    def test_legacy_expired_and_forged_verified_are_never_current_success(self):
        now = datetime.now(timezone.utc)
        legacy = probe.node_health({'is_online': 1, 'last_checked_at': now.isoformat()}, now)
        self.assertEqual(legacy['status'], 'expired')
        self.assertIn('历史入口', legacy['previous'])
        result = entry_result()
        result['status'] = 'verified'
        self.assertEqual(probe.node_health({'probe_result': json.dumps(result)}, now)['status'], 'entry')
        result['checked_at'] = (now - timedelta(minutes=16)).isoformat()
        self.assertEqual(probe.node_health({'probe_result': json.dumps(result)}, now)['status'], 'expired')
        self.assertEqual(probe.node_health({'probe_result': 'broken'})['status'], 'unknown')

    def test_budget_exhausted_before_tls_is_not_a_tls_failure(self):
        with mock.patch.object(probe.time, 'monotonic', side_effect=[0, 0, 0, 2, 2]), \
             mock.patch.object(probe.socket, 'create_connection', return_value=mock.Mock()), \
             mock.patch.object(probe.ssl, 'create_default_context') as tls:
            result = self.run_probe()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['stages']['tcp']['state'], 'success')
        self.assertEqual(result['stages']['tls']['state'], 'not_run')
        tls.assert_not_called()

    @unittest.skipUnless(shutil.which('openssl'), 'local TLS fixture needs openssl')
    def test_real_local_tls_valid_sni_and_mismatched_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'cert.cnf').write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=tls.example\n[ext]\nsubjectAltName=DNS:tls.example\nbasicConstraints=CA:TRUE\n")
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'), '-days', '1',
                '-config', str(root/'cert.cnf')], check=True, capture_output=True, timeout=15)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(root/'cert.pem', root/'key.pem')
            for sni, expected in (('tls.example', 'entry'), ('wrong.example', 'tls_error')):
                client_context = ssl.create_default_context(cafile=str(root/'cert.pem'))
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(3)
                    port = listener.getsockname()[1]
                    def serve():
                        try:
                            conn, _ = listener.accept()
                            with conn:
                                conn.settimeout(3)
                                with server_context.wrap_socket(conn, server_side=True):
                                    pass
                        except (ssl.SSLError, OSError):
                            pass
                    worker = threading.Thread(target=serve, daemon=True)
                    worker.start()
                    with mock.patch.object(probe.ssl, 'create_default_context', return_value=client_context):
                        result = probe.check_node_connect('entry.example', port, 2,
                            lambda *_: ['127.0.0.1'], allow_private=True,
                            node={'protocol':'trojan', 'host':'entry.example',
                                  'raw_uri':f'trojan://fake@entry.example:{port}?sni={sni}'})
                    worker.join(timeout=4)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(result['status'], expected)
                    self.assertEqual(result['stages']['tcp']['state'], 'success')
                    self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
                    self.assertEqual(result['stages']['access']['state'], 'not_run')


class NodeMonitorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        with mock.patch.dict(os.environ, {'ANYTLS_SECRET_KEY_FILE': str(root/'secret'),
                                         'ANYTLS_TRAFFIC_API_TOKEN_FILE': str(root/'traffic')}):
            self.module = load_app(root/'db')
        self.module.app.config.update(TESTING=True)
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)
        self.headers = {'X-CSRFToken': extract_csrf_token(self.client.get('/').text)}
        with self.module.app.app_context():
            db = self.module.get_db()
            for i in (1, 2):
                db.execute('INSERT INTO accounts(id,name,subscribe_url) VALUES(?,?,?)', (i, f'演示{i}', 'https://example.invalid'))
                db.execute('INSERT INTO nodes(id,account_id,name,host,port,password,raw_uri,protocol) VALUES(?,?,?,?,?,?,?,?)',
                    (i, i, f'节点{i}', 'entry.example', 443, f'fake-{i}', f'trojan://fake-{i}@entry.example:443?sni=tls{i}.example', 'trojan'))
            db.commit()

    def rows(self):
        with self.module.app.app_context():
            return [dict(n) for n in self.module.get_db().execute('SELECT * FROM nodes ORDER BY id')]

    def test_configuration_isolation_persistence_pages_and_api_error(self):
        with mock.patch.object(self.module, '_check_node_connect', return_value=entry_result()) as check:
            r = self.client.post('/api/nodes/1/check', headers=self.headers)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(check.call_args.kwargs['node']['password'], 'fake-1')
            self.assertEqual(r.json['health']['status'], 'entry')
        self.assertEqual(self.rows()[1]['probe_result'], '')
        before = self.rows()[0]['probe_result']
        for page in ('/nodes/monitor', '/accounts/1', '/'):
            response = self.client.get(page)
            self.assertEqual(response.status_code, 200)
            self.assertIn('入口可达', response.text)
            self.assertNotIn('>在线<', response.text)
        self.assertNotIn('fake-1', self.client.get('/nodes/monitor').text)
        with mock.patch.object(self.module, '_check_node_connect', side_effect=RuntimeError('secret-token')):
            error = self.client.post('/api/nodes/1/check', headers=self.headers)
        self.assertEqual(error.status_code, 503)
        self.assertEqual(error.json['health']['status'], 'error')
        self.assertNotIn('secret-token', error.text)
        self.assertEqual(self.rows()[0]['probe_result'], before)
        self.assertEqual(self.rows()[0]['is_online'], 1)
        self.assertIn('检测未完成', self.client.get('/nodes/monitor').text)
        self.assertEqual(self.client.post('/api/check-by-host', headers=self.headers,
            json={'host': 'entry.example', 'port': 443}).status_code, 409)

    def test_csrf_auth_private_policy_and_duplicate_global_limit(self):
        self.assertEqual(self.client.post('/api/nodes/1/check').status_code, 400)
        self.assertEqual(self.module.app.test_client().get('/nodes/monitor').status_code, 302)
        with self.module.app.app_context():
            token = self.module._acquire_probe(1)
        self.assertEqual(self.client.post('/api/nodes/1/check', headers=self.headers).status_code, 409)
        self.assertIn('检测中', self.client.get('/nodes/monitor').text)
        with self.module.app.app_context():
            self.module._save_probe(self.rows()[0], token, None)
        with mock.patch.object(self.module, '_resolve_subscription_addresses', return_value=['127.0.0.1']), \
             mock.patch.object(probe.socket, 'create_connection') as connect:
            response = self.client.post('/api/nodes/2/check', headers=self.headers)
        connect.assert_not_called()
        self.assertEqual(response.json['health']['status'], 'failed')
        with self.module.app.app_context():
            db = self.module.get_db()
            db.executemany('INSERT INTO node_probe_leases VALUES(?,?,?)', [(100+i, 'fake', time.time()+10) for i in range(8)])
            db.commit()
        self.assertEqual(self.client.post('/api/nodes/2/check', headers=self.headers).status_code, 409)

    def test_sync_preserves_exact_config_but_invalidates_credentials_and_sni(self):
        with mock.patch.object(self.module, '_check_node_connect', return_value=entry_result()):
            self.client.post('/api/nodes/1/check', headers=self.headers)
        original = self.rows()[0]
        with self.module.app.app_context():
            db = self.module.get_db()
            renamed = dict(original, name='新名称', raw_uri=original['raw_uri']+'#new')
            self.module._replace_account_nodes(db, 1, [renamed]); db.commit()
            saved = dict(db.execute('SELECT * FROM nodes WHERE account_id=1').fetchone())
            self.assertEqual(saved['probe_result'], original['probe_result'])
            changed = dict(renamed, raw_uri=original['raw_uri'].replace('tls1', 'tls2'))
            self.module._replace_account_nodes(db, 1, [changed]); db.commit()
            saved = dict(db.execute('SELECT * FROM nodes WHERE account_id=1').fetchone())
            self.assertEqual(saved['probe_result'], '')
            self.assertEqual(saved['is_online'], -1)

    def test_late_completion_cannot_overwrite_changed_config(self):
        node = self.rows()[0]
        with self.module.app.app_context():
            token = self.module._acquire_probe(1)
            db = self.module.get_db()
            db.execute("UPDATE nodes SET password='changed' WHERE id=1"); db.commit()
            self.module._save_probe(node, token, entry_result())
        self.assertEqual(self.rows()[0]['probe_result'], '')

    def test_batch_partial_exception_and_repeatable_migration(self):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute('UPDATE nodes SET account_id=1'); db.commit()
            self.module.apply_schema_migrations(db)
            self.module.apply_schema_migrations(db)
        with mock.patch.object(self.module, '_check_node_connect', side_effect=[entry_result(), RuntimeError('secret')]):
            r = self.client.post('/api/accounts/1/check-all', headers=self.headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual({i['health']['status'] for i in r.json['results']}, {'entry', 'error'})
        self.assertEqual(r.json['incomplete'], 1)
        self.assertNotIn('secret', r.text)
        self.assertEqual(self.rows()[1]['is_online'], -1)

    def test_abandoned_lease_is_not_a_node_failure_and_late_results_are_rejected(self):
        node = self.rows()[0]
        with self.module.app.app_context():
            token = self.module._acquire_probe(1)
            db = self.module.get_db()
            db.execute('UPDATE node_probe_leases SET expires=0 WHERE node_id=1'); db.commit()
            health = self.module._save_probe(node, token, entry_result())
            self.assertEqual(health['status'], 'error')
        self.assertEqual(self.rows()[0]['is_online'], -1)
        self.assertEqual(self.rows()[0]['probe_result'], '')
        response = self.client.get('/api/nodes/1/health')
        self.assertEqual(response.json['health']['status'], 'error')
        self.assertNotIn('fake-1', response.text)

    def test_batch_deadline_leaves_unstarted_nodes_unchanged(self):
        real_clock = time.monotonic
        deadline_passed = False
        def clock():
            return real_clock() + (30 if deadline_passed else 0)
        def slow_result(*args, **kwargs):
            nonlocal deadline_passed
            deadline_passed = True
            return entry_result()
        with self.module.app.app_context():
            db = self.module.get_db()
            db.executemany('INSERT INTO nodes(account_id,name,host,port,password) VALUES(1,?,?,443,?)',
                [(f'node{i}', 'example.invalid', 'fake') for i in range(10)])
            db.commit()
        with mock.patch.object(self.module.time, 'monotonic', side_effect=clock), \
             mock.patch.object(self.module, '_check_node_connect', side_effect=slow_result):
            response = self.client.post('/api/accounts/1/check-all', headers=self.headers)
        self.assertGreater(response.json['incomplete'], 0)
        self.assertEqual(self.rows()[-1]['probe_result'], '')

    def test_batch_lock_is_shared_across_worker_local_mutexes(self):
        with self.module.app.app_context():
            self.module._acquire_probe(-1)
        self.assertEqual(self.client.post('/api/accounts/1/check-all', headers=self.headers).status_code, 409)
