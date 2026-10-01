"""Regression checks for the fourth sequential five-round audit."""
from pathlib import Path
from contextlib import closing
import tempfile
import os
import hashlib
import io
import sqlite3
import subprocess
import sys
import tarfile
import unittest
from unittest import mock

import node_monitor
import protocol_codecs
import yaml
from test_bug_review_round5 import vmess_uri
from test_app import authenticate_session, load_app


class FourthFiveRoundAudit(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_round_one_expired_monitor_budget_does_not_start_network(self):
        panel = load_app(self.root / 'panel.db')
        with panel.app.app_context():
            db = panel.get_db()
            db.execute("INSERT INTO accounts(name, subscribe_url) VALUES ('fixture', 'fixture')")
            db.execute("""INSERT INTO nodes(account_id, name, host, port, password, raw_uri)
                       VALUES (1, 'fixture', 'node.example', 443, 'synthetic',
                               'anytls://synthetic@node.example:443')""")
            db.commit()
        clock = [0.0]
        original_acquire = panel._acquire_probe

        def acquire(node_id):
            token = original_acquire(node_id)
            clock[0] = 46.0
            return token

        with mock.patch.object(node_monitor.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(panel, '_acquire_probe', side_effect=acquire), \
                mock.patch.object(panel, '_run_probe', return_value=None) as probe:
            report = node_monitor.check_due_nodes(panel)
        probe.assert_not_called()
        self.assertEqual(report['incomplete'], 1)
        with panel.app.app_context():
            self.assertIsNotNone(panel._acquire_probe(1))

    def test_round_two_numeric_collector_cannot_reset_string_identity(self):
        token_file = self.root / 'token'
        token_file.write_text('fixture-token')
        environment = mock.patch.dict(os.environ, {'ANYTLS_TRAFFIC_API_TOKEN_FILE': str(token_file)})
        environment.start()
        self.addCleanup(environment.stop)
        panel = load_app(self.root / 'counter.db')
        panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with panel.app.app_context():
            db = panel.get_db()
            db.execute("INSERT INTO accounts(name, subscribe_url) VALUES ('fixture', 'fixture')")
            db.commit()
        client = panel.app.test_client()
        headers = {'Authorization': 'Bearer fixture-token'}

        def send(identity, counter):
            return client.post('/api/traffic/counter', headers=headers, json={
                'collector_id': identity, 'account_id': 1, 'counter_bytes': counter})

        self.assertEqual(send('12345678', 100).status_code, 200)
        for identity in (12345678, True, None, [], {}):
            with self.subTest(identity=identity):
                self.assertEqual(send(identity, 50).status_code, 400)
        response = send('12345678', 120)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['delta_bytes'], 20)
        self.assertEqual(response.get_json()['total_bytes'], 20)

    def test_round_three_invalid_vmess_cipher_and_alter_id_are_rejected(self):
        for field, values in (('scy', [[], {}, True, 1]),
                              ('aid', [True, False, 1.9, [], {}, -1, '-1'])):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertIsNone(protocol_codecs.parse_protocol_uri(
                        vmess_uri(**{field: value}), 'vmess'))
        for aid, expected in ((0, 0), ('0', 0), (64, 64), ('64', 64), ('invalid', 0)):
            node = protocol_codecs.parse_protocol_uri(vmess_uri(aid=aid, scy='auto'), 'vmess')
            proxy = protocol_codecs.clash_proxy_from_uri(node['raw_uri'])
            self.assertEqual(proxy['alterId'], expected)
            self.assertEqual(proxy['cipher'], 'auto')

    def test_round_three_invalid_vmess_yaml_does_not_hide_valid_peer(self):
        valid = dict(name='valid', type='vmess', server='fixture.example', port=443,
                     uuid='00000000-0000-4000-8000-000000000001', cipher='auto', alterId=0)
        for field, value in (('cipher', ['auto']), ('cipher', True),
                             ('alterId', True), ('alterId', 1.9), ('alterId', -1)):
            source = yaml.safe_dump({'proxies': [dict(valid, name='bad', **{field: value}), valid]})
            with self.subTest(field=field, value=value):
                self.assertEqual([node['name'] for node in protocol_codecs.parse_clash_yaml(source)], ['valid'])

    def test_round_four_backup_verifier_rejects_corruption_and_unsafe_members(self):
        database = self.root / 'backup.db'
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('CREATE TABLE fixture(value TEXT)')
            db.execute("INSERT INTO fixture VALUES ('synthetic')")
        script = (Path(__file__).resolve().parents[1] / 'backup.sh').read_text()
        verifier = script.split("\"$PYTHON_BIN\" - \"$archive\" <<'PY'\n", 1)[1].split('\nPY', 1)[0]
        valid = database.read_bytes()
        for scenario in ('valid', 'corrupt', 'traversal', 'duplicate'):
            with self.subTest(scenario=scenario):
                contents = {'anytls.db': b'invalid sqlite' if scenario == 'corrupt' else valid}
                if scenario == 'traversal':
                    contents['../outside'] = b'synthetic'
                contents['SHA256SUMS'] = ''.join(
                    f'{hashlib.sha256(body).hexdigest()}  ./{name}\n'
                    for name, body in contents.items()).encode()
                archive = self.root / f'{scenario}.tar.gz'
                with tarfile.open(archive, 'w:gz') as bundle:
                    for name, body in contents.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(body)
                        bundle.addfile(member, io.BytesIO(body))
                    if scenario == 'duplicate':
                        member = tarfile.TarInfo('anytls.db')
                        member.size = len(valid)
                        bundle.addfile(member, io.BytesIO(valid))
                result = subprocess.run([sys.executable, '-c', verifier, str(archive)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, scenario == 'valid', result.stderr)
        self.assertFalse((self.root / 'outside').exists())

    def test_round_five_vmess_import_export_and_failed_sync_preserve_cache(self):
        valid = dict(name='valid', type='vmess', server='fixture.example', port=443,
                     uuid='00000000-0000-4000-8000-000000000001', cipher='auto', alterId=0)
        sources = (
            ('uri', vmess_uri(ps='valid'), vmess_uri(ps='bad', aid=True)),
            ('yaml', yaml.safe_dump({'proxies': [valid]}),
             yaml.safe_dump({'proxies': [dict(valid, name='bad', cipher=['auto'])]})),
        )
        for kind, good, bad in sources:
            with self.subTest(kind=kind):
                panel = load_app(self.root / f'{kind}.db')
                panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
                client = panel.app.test_client()
                authenticate_session(panel, client)
                mixed = '\n'.join((bad, good)) if kind == 'uri' else yaml.safe_dump({
                    'proxies': [dict(valid, name='bad', cipher=['auto']), valid]})
                response = client.post('/accounts/add', data={'name': kind, 'subscribe_url': mixed})
                self.assertEqual(response.status_code, 302)
                with panel.app.app_context():
                    db = panel.get_db()
                    self.assertEqual([row['name'] for row in db.execute('SELECT name FROM nodes')], ['valid'])
                    token = f'fixture-{kind}'
                    db.execute('UPDATE accounts SET sub_token=? WHERE id=1', (token,))
                    db.execute('UPDATE accounts SET subscribe_url=? WHERE id=1', (bad,))
                    db.commit()
                self.assertEqual(client.post('/accounts/1/sync').status_code, 302)
                bulk = client.post('/api/sync-all')
                self.assertEqual(bulk.status_code, 200)
                self.assertEqual(bulk.get_json()['results'][0]['status'], 'error')
                exported = client.get(f'/sub/{token}?format=clash')
                self.assertEqual(exported.status_code, 200)
                proxies = yaml.safe_load(exported.data)['proxies']
                self.assertEqual(len(proxies), 1)
                self.assertEqual(proxies[0]['name'], 'valid')
                self.assertEqual(proxies[0]['cipher'], 'auto')
                self.assertEqual(proxies[0]['alterId'], 0)
