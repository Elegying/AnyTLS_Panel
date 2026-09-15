import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_app import authenticate_session, extract_csrf_token, load_app


class FormFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        with mock.patch.dict(os.environ, {
            'ANYTLS_SECRET_KEY_FILE': str(root / 'secret'),
            'ANYTLS_TRAFFIC_API_TOKEN_FILE': str(root / 'traffic'),
        }):
            self.module = load_app(root / 'panel.db')
        self.module.app.config.update(TESTING=True)
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)
        token = extract_csrf_token(self.client.get('/services').get_data(as_text=True))
        self.headers = {'X-Panel-Form': '1', 'X-CSRFToken': token}
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO accounts(name,subscribe_url) VALUES('demo','https://example.invalid')")
            db.commit()

    def values(self, **changes):
        values = dict(account_id='1', wechat_id='演示用户', relationship='自用',
                      started_on='2026-09-15', expires_on='2026-10-15', notes='保留备注')
        values.update(changes)
        return values

    def test_validation_returns_field_and_no_write(self):
        response = self.client.post('/services/add', headers=self.headers,
                                    data=self.values(expires_on='2026-09-14'))
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json['field'], 'expires_on')
        self.assertIn('不能早于', response.json['error'])
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute(
                'SELECT COUNT(*) FROM customer_services').fetchone()[0], 0)

    def test_create_duplicate_edit_renew_and_fixed_return(self):
        response = self.client.post('/services/add', headers=self.headers, data=self.values())
        self.assertEqual(response.json, {'redirect': '/services/1'})
        duplicate = self.client.post('/services/add', headers=self.headers, data=self.values())
        self.assertEqual(duplicate.status_code, 422)
        invalid = self.client.post('/services/1/edit', headers=self.headers,
                                   data=self.values(expires_on='2026-09-14'))
        self.assertEqual(invalid.status_code, 422)
        shorter = self.client.post('/services/1/renew', headers=self.headers,
                                  data={'new_expires_on': '2026-09-16'})
        self.assertEqual(shorter.status_code, 422)
        self.assertEqual(shorter.json['field'], 'new_expires_on')
        renewed = self.client.post('/services/1/renew', headers=self.headers,
                                  data={'new_expires_on': '2026-11-15', 'return_to': 'dashboard'})
        self.assertEqual(renewed.json, {'redirect': '/#attention-title'})
        renewed = self.client.post('/services/1/renew', headers=self.headers,
                                  data={'new_expires_on': '2026-12-15', 'return_to': '//evil.example'})
        self.assertEqual(renewed.json, {'redirect': '/services/1'})
        missing = self.client.post('/services/999/renew', headers=self.headers,
                                   data={'new_expires_on': '2026-12-15'})
        self.assertEqual(missing.status_code, 422)
        self.assertIn('不存在', missing.json['error'])
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute(
                'SELECT COUNT(*) FROM customer_services').fetchone()[0], 1)

    def test_import_error_and_csrf_still_enforced(self):
        with mock.patch.object(self.module, 'parse_subscribe_url', side_effect=ValueError('订阅无法解析')):
            response = self.client.post('/accounts/add', headers=self.headers,
                                        data={'subscribe_url': 'https://example.invalid', 'name': '草稿'})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json['field'], 'subscribe_url')
        response = self.client.post('/services/add', headers={'X-Panel-Form': '1'}, data=self.values())
        self.assertEqual(response.status_code, 400)

    def test_monitor_timestamp_and_durable_probe_state(self):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO nodes(account_id,name,host,port,password) VALUES(1,'demo','example.invalid',443,'fake')")
            db.commit()
        with mock.patch.object(self.module, '_check_node_connect', return_value={'online': True, 'latency': 12}):
            response = self.client.post('/api/check-by-host', headers=self.headers,
                                        json={'host': 'example.invalid', 'port': 443})
        self.assertTrue(response.json['online'])
        self.assertRegex(response.json['checked_at'], r'^\d{4}-\d{2}-\d{2} .* UTC$')
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute('SELECT is_online FROM nodes').fetchone()[0], 1)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for browser logic unit tests')
    def test_frontend_feedback_regressions(self):
        result = subprocess.run(
            ['node', '--test', str(Path(__file__).with_name('ui-feedback.test.cjs'))],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
