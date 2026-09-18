import base64
import json
import tempfile
import unittest
from pathlib import Path

from test_app import load_app, authenticate_session, extract_csrf_token


class NodeFilterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.module = load_app(Path(self.tmp.name) / 'panel.db')
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO accounts (name, subscribe_url, sub_token) VALUES ('demo', '', 'demo-token')")
            for name in ['香港 TEST', '东京正常', '测试线路']:
                db.execute('INSERT INTO nodes (account_id,name,host,port,password,protocol,raw_uri) VALUES (1,?,?,?,?,?,?)',
                           (name, 'example.com', 443, 'fake', 'trojan', 'trojan://fake@example.com:443#' + name))
            db.execute("INSERT INTO customer_services (account_id,wechat_id,started_on,expires_on,sub_token) VALUES (1,'demo','2020-01-01','2099-01-01','service-token')")
            db.commit()
        self.csrf = extract_csrf_token(self.client.get('/settings/rename-rules').get_data(as_text=True))

    def save(self, keywords, enabled=True):
        return self.client.post('/settings/node-filter', data={
            'csrf_token': self.csrf, 'keywords': keywords, 'enabled': '1' if enabled else '0'})

    def test_filter_all_exports_persistence_and_disable(self):
        self.assertEqual(self.save(' test \n测试\n\n test ').status_code, 302)
        self.module.init_db()  # Repeated initialization preserves settings.
        for token in ['demo-token', 'service-token']:
            response = self.client.get('/sub/' + token)
            body = base64.b64decode(response.data).decode()
            self.assertIn('东京正常', body)
            self.assertNotIn('TEST', body)
            self.assertNotIn('测试线路', body)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            import yaml
            clash = self.client.get('/sub/' + token, headers={'User-Agent': 'Clash'})
            self.assertEqual([p['name'] for p in yaml.safe_load(clash.data)['proxies']], ['东京正常'])
        self.assertEqual(self.client.get('/api/subscribe').json['count'], 1)
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute('SELECT COUNT(*) FROM nodes').fetchone()[0], 3)
        self.save('test\n测试', enabled=False)
        self.assertEqual(self.client.get('/api/subscribe').json['count'], 3)

    def test_empty_all_blocked_original_name_and_input_bounds(self):
        self.save('')
        self.assertEqual(self.client.get('/api/subscribe').json['count'], 3)
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO rename_rules (old_text,new_text) VALUES ('TEST','SAFE')")
            db.commit()
        self.save('test\n东京\n测试')
        self.assertEqual(self.client.get('/sub/demo-token').status_code, 200)
        self.assertEqual(self.client.get('/sub/demo-token').data, b'')
        self.assertEqual(self.client.get('/api/subscribe').json['count'], 0)
        self.assertEqual(self.save('x' * 129).status_code, 422)
        self.assertEqual(self.client.get('/api/subscribe').json['count'], 0)
        self.assertEqual(self.save('\n'.join(str(i) for i in range(101))).status_code, 422)

    def test_csrf_and_login_required(self):
        self.assertEqual(self.client.post('/settings/node-filter', data={'keywords': 'test'}).status_code, 400)
        anonymous = self.module.app.test_client()
        self.assertEqual(anonymous.get('/settings/rename-rules').status_code, 302)
        with self.module.app.app_context():
            self.assertEqual(json.loads(self.module.get_db().execute('SELECT keywords FROM node_filter').fetchone()[0]), [])

    def test_dashboard_does_not_render_node_list_or_pending_payload(self):
        with self.module.app.app_context():
            db = self.module.get_db()
            db.executemany('INSERT INTO nodes (account_id,name,host,port,password) VALUES (1,?,?,443,?)',
                           [('large-node-' + str(i), 'example.com', 'fake') for i in range(1000)])
            db.commit()
        html = self.client.get('/').get_data(as_text=True)
        self.assertNotIn('large-node-', html)
        self.assertNotIn('香港 TEST', html)
        self.assertIn('data-states="[]"', html)
        self.assertIn('data-total="1003"', html)
        self.assertIn('查看节点监控', html)
        self.assertLess(len(html.encode()), 60000)
