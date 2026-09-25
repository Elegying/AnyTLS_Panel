"""Authentication isolation, resource limits and scheduled probe regressions."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from test_app import load_app, authenticate_session
from test_reliability import run_shell
from probe_fixtures import entry_result
import test_audit_fixes
import proxy_verifier as verifier
import node_monitor


class ProxyVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'panel.db'
        self.module = load_app(self.database)
        self.module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)

    account = test_audit_fixes.AuditFixTests.account

    def test_controller_socket_before_proxy_configuration_is_not_ready(self):
        process = mock.Mock()
        process.poll.return_value = None
        response = mock.Mock()
        response.status = 200
        response.read.return_value = b'{"name":"health-probe"}'
        initializing = mock.Mock()
        initializing.status = 404
        initializing.read.return_value = b'{"message":"Not Found"}'
        connection = mock.Mock()
        connection.getresponse.side_effect = [initializing, response]
        with mock.patch.object(verifier, 'UnixHTTPConnection', return_value=connection):
            verifier.wait_for_proxy('/fictional/controller', process, time.monotonic() + 1)
        self.assertEqual(connection.request.call_count, 2)
        self.assertEqual(connection.close.call_count, 2)
        process.poll.return_value = 1
        with self.assertRaises(RuntimeError):
            verifier.wait_for_proxy('/fictional/controller', process, time.monotonic() + 1)

    @unittest.skipUnless(os.name == 'posix', 'production POSIX locks')
    def test_core_slots_bound_threads_and_release_after_exception(self):
        with verifier.core_slot(self.temp.name) as first, verifier.core_slot(self.temp.name) as second:
            self.assertTrue(first and second)
            with verifier.core_slot(self.temp.name) as third:
                self.assertFalse(third)
        with verifier.core_slot(self.temp.name) as again:
            self.assertTrue(again)

    @unittest.skipUnless(os.name == 'posix', 'production POSIX locks')
    def test_actual_access_result_controls_auth_and_private_dns_never_starts_core(self):
        node = dict(name='test', protocol='trojan', host='example.com', port=443,
                    password='secret-fixture', raw_uri='trojan://secret-fixture@example.com:443')
        with mock.patch.object(verifier, 'run_core', return_value=47) as core, \
                mock.patch('node_probe.socket.create_connection', side_effect=OSError):
            result = verifier.verify_node_proxy(node, lambda *_: ['127.0.0.1'], self.temp.name)
            self.assertNotEqual(result['status'], 'verified')
            core.assert_not_called()
            result = verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8'], self.temp.name)
            self.assertEqual(result['status'], 'verified')
            self.assertEqual(result['proxy_latency'], 47)
            self.assertEqual(core.call_args.args[0]['server'], '8.8.8.8')
            self.assertEqual(core.call_args.args[0]['sni'], 'example.com')
            self.assertNotIn('secret-fixture', json.dumps(result))
            core.side_effect = verifier.ProxyAccessFailed('secret-fixture from untrusted core error')
            result = verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8'], self.temp.name)
            self.assertEqual(result['status'], 'failed')
            self.assertNotEqual(result['stages']['auth']['state'], 'success')
            self.assertNotIn('secret-fixture', json.dumps(result))

    def test_url_specific_completed_evidence_controls_result_not_controller_status(self):
        process = mock.Mock()
        process.poll.return_value = 0
        for status, alive, delay in ((200, True, 47), (200, False, 0),
                                      (503, False, 0), (504, False, 0), (503, True, 0)):
            with self.subTest(status=status, alive=alive, delay=delay):
                snapshot = {'name': 'health-probe', 'alive': True,
                            'extra': {verifier.PROBE_URL: {'alive': alive, 'history': [{'delay': delay}]}}}
                with mock.patch.object(verifier.subprocess, 'Popen', return_value=process), \
                        mock.patch.object(verifier, 'wait_for_proxy'), \
                        mock.patch.object(verifier, 'core_response', side_effect=[
                            (status, {'delay': 47}), (200, snapshot)]) as responses:
                    if alive:
                        self.assertEqual(verifier.run_core({}, self.temp.name, time.monotonic()+2), delay)
                    else:
                        with self.assertRaises(verifier.ProxyAccessFailed):
                            verifier.run_core({}, self.temp.name, time.monotonic()+2)
                    self.assertIn('expected=204', responses.call_args_list[0].args[1])
                self.assertFalse(list(Path(self.temp.name).glob('probe-*')))

    def test_incomplete_or_malformed_core_evidence_is_not_a_node_failure(self):
        process = mock.Mock()
        process.poll.return_value = 0
        for extra in (None, [], {}, {verifier.PROBE_URL: []},
                      {verifier.PROBE_URL: {'alive': True, 'history': []}},
                      {verifier.PROBE_URL: {'alive': True, 'history': [{'delay': True}]}}):
            with self.subTest(extra=extra), \
                    mock.patch.object(verifier.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(verifier, 'wait_for_proxy'), \
                    mock.patch.object(verifier, 'core_response', side_effect=[
                        (200, {'delay': 47}), (200, {'name': 'health-probe', 'alive': True, 'extra': extra})]):
                with self.assertRaises(ValueError):
                    verifier.run_core({}, self.temp.name, time.monotonic()+2)

    def test_core_task_errors_preserve_last_completed_evidence_after_api_refresh(self):
        self.account()
        completed = entry_result()
        completed['version'] = 2
        completed['status'] = 'verified'
        for stage in ('auth', 'access'):
            completed['stages'][stage] = {'state': 'success', 'detail': 'synthetic completed evidence'}
        with mock.patch.object(self.module, '_run_probe', return_value=completed):
            self.assertEqual(self.client.post('/api/nodes/1/check').json['status'], 'verified')
        with self.module.app.app_context():
            previous = self.module.get_db().execute('SELECT probe_result FROM nodes WHERE id=1').fetchone()[0]
        for error in (RuntimeError, OSError, ValueError, verifier.http.client.HTTPException):
            with self.subTest(error=error.__name__), \
                    mock.patch.object(self.module, '_proxy_verification_enabled', return_value=True), \
                    mock.patch.object(self.module, '_resolve_subscription_addresses', return_value=['8.8.8.8']), \
                    mock.patch('node_probe.socket.create_connection', side_effect=OSError), \
                    mock.patch.object(verifier, 'run_core', side_effect=error('private-fixture-error')):
                response = self.client.post('/api/nodes/1/check')
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json['status'], 'error')
                self.assertNotIn('private-fixture-error', response.text)
                refreshed = self.client.get('/api/nodes/1/health')
                self.assertEqual(refreshed.json['status'], 'error')
                self.assertEqual(refreshed.json['health']['previous'], '代理验证通过')
                with self.module.app.app_context():
                    row = self.module.get_db().execute('SELECT * FROM nodes WHERE id=1').fetchone()
                    self.assertEqual(row['probe_result'], previous)
                    self.assertEqual(row['is_online'], 1)
                    self.assertTrue(row['probe_error'])

    def test_address_pinning_preserves_implicit_and_explicit_websocket_host(self):
        for protocol in ('vmess', 'vless', 'trojan'):
            for host_key, host_value in ((None, None), ('Host', 'front.example'),
                                          ('host', 'front.example'), ('HOST', '')):
                with self.subTest(protocol=protocol, header=host_key, value=host_value):
                    headers = {'X-Fixture': 'preserved'}
                    if host_key:
                        headers[host_key] = host_value
                    proxy = dict(type=protocol, server='entry.example', port=443, network='ws', tls=True,
                                 servername='tls.example', sni='tls.example', **{'ws-opts': {'headers': headers}})
                    node = dict(host='entry.example', port=443, protocol=protocol, raw_uri='',
                                clash_config=json.dumps(proxy))
                    with mock.patch.object(verifier, 'run_core', return_value=47) as core, \
                            mock.patch('node_probe.socket.create_connection', side_effect=OSError):
                        result = verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8'], self.temp.name)
                    self.assertEqual(result['status'], 'verified')
                    pinned = core.call_args.args[0]
                    self.assertEqual(pinned['server'], '8.8.8.8')
                    self.assertEqual(pinned['sni' if protocol == 'trojan' else 'servername'], 'tls.example')
                    self.assertEqual({k.lower(): v for k, v in pinned['ws-opts']['headers'].items()},
                                     {'x-fixture': 'preserved', 'host': host_value or 'entry.example'})
                    self.assertEqual(json.loads(node['clash_config']), proxy)

    def test_different_credentials_are_separate_when_proxy_verification_enabled(self):
        for password in ('one', 'two'):
            self.account([dict(type='trojan', name='same', server='example.com', port=443, password=password)], name=password)
        with mock.patch.object(self.module, '_proxy_verification_enabled', return_value=True):
            page = self.client.get('/nodes/monitor').text
        self.assertIn('2 个配置组', page)
        self.assertIn('每个节点自己的凭据', page)

    def test_scheduler_is_bounded_fair_and_preserves_existing_evidence_on_errors(self):
        self.account([dict(type='trojan', name=str(i), server='example.com', port=443+i, password='fake') for i in range(5)])
        attempts = []

        def fail(node, timeout=8):
            attempts.append(node['id'])
            self.assertLessEqual(timeout, 8)
            raise OSError('fixture failure')

        with mock.patch.object(self.module, '_run_probe', side_effect=fail):
            node_monitor.check_due_nodes(self.module, limit=2)
            node_monitor.check_due_nodes(self.module, limit=2)
        self.assertEqual(attempts, [1, 2, 3, 4])
        with self.module.app.app_context():
            db = self.module.get_db()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM node_probe_leases').fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM nodes WHERE probe_error<>''").fetchone()[0], 4)

    def test_monitor_units_bind_to_panel_and_have_hard_budgets(self):
        result = run_shell('install-monitor.sh', r'''
PANEL_DIR=/opt/panel
SERVICE_NAME=panel
SERVICE_USER=panel
UNIT_DIR="$TEST_ROOT"
write_monitor_units
''', TEST_ROOT=self.temp.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        service = (Path(self.temp.name) / 'panel-monitor.service').read_text()
        self.assertIn('BindsTo=panel.service', service)
        self.assertIn('ConditionPathExists=/opt/panel/node_monitor.py', service)
        self.assertIn('TimeoutStartSec=55s', service)
        self.assertIn('MemoryMax=224M', service)
