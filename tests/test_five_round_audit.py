"""Regression checks from the sequential five-round bug audit."""
import tempfile
import unittest
from pathlib import Path
import subprocess
import base64
from urllib.parse import parse_qs, urlparse

from test_app import authenticate_session, load_app
from traffic_token import make_account_traffic_token
from protocol_codecs import clash_proxy_from_uri, parse_clash_yaml, uri_preserves_clash_config
from subscription_export import prepare_subscription
import yaml


class FiveRoundAudit(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_round_one_token_rejects_ids_that_would_be_truncated(self):
        for account_id in (1.9, 1.0, True, None, [], float('inf')):
            with self.subTest(account_id=account_id):
                with self.assertRaises(ValueError):
                    make_account_traffic_token('synthetic-master', account_id)
        self.assertEqual(make_account_traffic_token('synthetic-master', '12'),
                         make_account_traffic_token('synthetic-master', 12))
        self.assertNotEqual(make_account_traffic_token('synthetic-master', 12),
                            make_account_traffic_token('synthetic-master', 1))

    def test_round_two_batch_distinguishes_missing_and_empty_accounts(self):
        panel = load_app(self.root / 'panel.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        client = panel.app.test_client()
        authenticate_session(panel, client)
        response = client.post('/api/accounts/999/check-all')
        self.assertEqual(response.status_code, 404)
        with panel.app.app_context():
            db = panel.get_db()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM node_probe_leases').fetchone()[0], 0)
            db.execute("INSERT INTO accounts(name, subscribe_url) VALUES ('empty', 'fixture')")
            db.commit()
        response = client.post('/api/accounts/1/check-all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'results': [], 'total': 0, 'incomplete': 0})
        with panel.app.app_context():
            self.assertEqual(panel.get_db().execute('SELECT COUNT(*) FROM node_probe_leases').fetchone()[0], 0)

    def test_round_three_hysteria_default_port_and_certificate_pin_survive(self):
        fingerprint = ':'.join(['AB'] * 32)
        for scheme in ('hysteria2', 'hy2'):
            for authority, port in (('node.example', 443), ('[2001:db8::1]', 443),
                                    ('node.example:8443', 8443)):
                with self.subTest(scheme=scheme, authority=authority):
                    proxy = clash_proxy_from_uri(
                        f'{scheme}://synthetic@{authority}?insecure=1&pinSHA256={fingerprint}')
                    self.assertEqual(proxy['port'], port)
                    self.assertEqual(proxy['fingerprint'], fingerprint)
                    self.assertTrue(proxy['skip-cert-verify'])
                    nodes = parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))
                    self.assertEqual(len(nodes), 1)
                    self.assertTrue(uri_preserves_clash_config(proxy, nodes[0]['raw_uri']))
                    exported = prepare_subscription(nodes, [], [])
                    self.assertEqual(exported['proxies'][0]['fingerprint'], fingerprint)
                    self.assertFalse(exported['requires_clash'])
                    restored = clash_proxy_from_uri(exported['links'][0])
                    self.assertEqual(restored['fingerprint'], fingerprint)
        self.assertIsNone(clash_proxy_from_uri('trojan://synthetic@node.example'))
        self.assertIsNone(clash_proxy_from_uri('hy2://synthetic@node.example:invalid'))
        self.assertIsNone(clash_proxy_from_uri('hy2://synthetic@node.example:0'))

    def test_round_four_shell_numeric_limits_are_decimal_and_cannot_wrap(self):
        root = Path(__file__).resolve().parent.parent
        cases = [('backup.sh', 'RETENTION_COUNT', 2, 365),
                 ('deploy.sh', 'BACKUP_RETENTION_COUNT', 2, 365),
                 ('deploy.sh', 'PORT', 1, 65535),
                 ('deploy.sh', 'TRAFFIC_LOG_RETENTION_DAYS', 1, 3650),
                 ('deploy.sh', 'MAX_REQUEST_BYTES', 65536, 16777216)]
        for filename, variable, minimum, maximum in cases:
            source = (root / filename).read_text()
            start = source.index(f'    if ! [[ "${variable}" =~')
            bound = source.index(f'    if (( {variable} <', start)
            end = source.index('    fi', bound) + len('    fi')
            # Exercise actual validators without root, deployment or backup mutations.
            body = source[start:end]
            values = [(str(minimum), True), (str(maximum), True),
                      ('000' + str(minimum), True), ('000' + str(maximum), True),
                      (str(minimum - 1), False), (str(maximum + 1), False),
                      (str(2**64 + minimum), False), ('1+1', False), ('-1', False)]
            if minimum <= 20 <= maximum:
                values.extend([('08', True), ('020', True), ('0400', 400 <= maximum)])
            for value, valid in values:
                with self.subTest(filename=filename, variable=variable, value=value):
                    command = (f'set -e\nfail() {{ exit 1; }}\n{variable}="$1"\n'
                               + body + f'\nprintf "%s" "${variable}"')
                    result = subprocess.run(['bash', '-c', command, 'fixture', value],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode == 0, valid, result.stderr)
                    if valid:
                        self.assertEqual(result.stdout, str(int(value)))

    def test_round_five_import_store_export_and_disabled_account_policy(self):
        panel = load_app(self.root / 'panel.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        client = panel.app.test_client()
        authenticate_session(panel, client)
        fingerprint = ':'.join(['AB'] * 32)
        uri = f'hy2://synthetic@node.example?insecure=1&pinSHA256={fingerprint}#fixture'
        response = client.post('/accounts/add', data={
            'name': 'fixture', 'subscribe_url': uri, 'traffic_limit_gb': '250'})
        self.assertEqual(response.status_code, 302)
        with panel.app.app_context():
            db = panel.get_db()
            node = db.execute('SELECT * FROM nodes').fetchone()
            self.assertEqual(node['port'], 443)
            self.assertEqual(node['raw_uri'], uri)
            db.execute("UPDATE accounts SET sub_token='synthetic-share' WHERE id=1")
            db.commit()
        response = client.get('/sub/synthetic-share?format=clash')
        self.assertEqual(response.status_code, 200)
        proxy = yaml.safe_load(response.data)['proxies'][0]
        self.assertEqual(proxy['fingerprint'], fingerprint)
        self.assertTrue(proxy['skip-cert-verify'])
        response = client.get('/sub/synthetic-share?format=base64')
        self.assertEqual(response.status_code, 200)
        restored = clash_proxy_from_uri(base64.b64decode(response.data).decode())
        self.assertEqual(restored['fingerprint'], fingerprint)
        self.assertNotIn('Subscription-Userinfo', response.headers)
        with panel.app.app_context():
            db = panel.get_db()
            db.execute("UPDATE accounts SET status='disabled' WHERE id=1")
            db.commit()
        self.assertEqual(client.get('/sub/synthetic-share?format=clash').status_code, 404)
        self.assertEqual(client.get('/sub/synthetic-share?format=base64').status_code, 404)

    def test_round_five_hysteria_export_uses_standard_insecure_parameter(self):
        for insecure in (False, True):
            with self.subTest(insecure=insecure):
                proxy = {'type': 'hysteria2', 'name': 'fixture', 'server': 'node.example',
                         'port': 443, 'password': 'synthetic', 'skip-cert-verify': insecure}
                nodes = parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))
                query = parse_qs(urlparse(nodes[0]['raw_uri']).query)
                self.assertEqual(query.get('insecure'), ['1' if insecure else '0'])
                self.assertEqual(clash_proxy_from_uri(nodes[0]['raw_uri'])['skip-cert-verify'], insecure)
