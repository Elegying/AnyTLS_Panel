"""Authentication isolation, resource limits and scheduled probe regressions."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_app import load_app, authenticate_session
from test_reliability import run_shell
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
            core.side_effect = OSError('secret-fixture from untrusted core error')
            result = verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8'], self.temp.name)
            self.assertEqual(result['status'], 'failed')
            self.assertNotEqual(result['stages']['auth']['state'], 'success')
            self.assertNotIn('secret-fixture', json.dumps(result))

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
