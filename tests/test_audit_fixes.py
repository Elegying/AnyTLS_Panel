"""End-to-end regressions for the September reliability review."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_app import load_app, authenticate_session
from test_reliability import run_shell


class AuditFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'panel.db'
        self.module = load_app(self.database)
        self.module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)

    def account(self, proxies=None, name='account'):
        nodes = self.module._parse_clash_yaml(yaml.safe_dump({'proxies': proxies or [
            {'name': 'one', 'type': 'trojan', 'server': 'example.com', 'port': 443, 'password': 'fake'},
        ]}))
        with self.module.app.app_context():
            db = self.module.get_db()
            account_id = db.execute(
                'INSERT INTO accounts(name,subscribe_url,sub_token) VALUES (?,?,?)',
                (name, 'https://example.com/' + name, name),
            ).lastrowid
            self.module._replace_account_nodes(db, account_id, nodes)
            db.commit()
        return account_id

    def test_clash_options_survive_storage_and_export_without_lossy_generic_output(self):
        proxy = {'name': 'advanced', 'type': 'tuic', 'server': 'example.com', 'port': 443,
                 'uuid': '00000000-0000-4000-8000-000000000001', 'password': 'fake',
                 'alpn': ['h3'], 'congestion-controller': 'bbr', 'udp-relay-mode': 'quic',
                 'ip-version': 'ipv4'}
        self.account([proxy])
        response = self.client.get('/sub/account?format=clash')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(yaml.safe_load(response.data)['proxies'], [proxy])
        self.assertEqual(self.client.get('/sub/account').status_code, 406)
        self.assertEqual(self.client.get('/api/subscribe').status_code, 406)
        self.assertEqual(yaml.safe_load(self.client.get('/sub/account', headers={'User-Agent': 'SSRVPN/4'}).data)['proxies'], [proxy])
        self.assertIn('Clash', self.client.get('/accounts/1').text)

    def test_common_alpn_and_tuic_options_roundtrip_in_generic_links(self):
        for protocol, extra in [('trojan', {'alpn': ['h2', 'http/1.1']}),
                                ('tuic', {'uuid': 'uuid', 'alpn': ['h3'], 'congestion-controller': 'bbr', 'udp-relay-mode': 'quic'})]:
            proxy = {'name': 'test', 'type': protocol, 'server': 'example.com', 'port': 443, 'password': 'fake', **extra}
            node = self.module._parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]
            restored = self.module._clash_proxy_from_uri(node['raw_uri'])
            for key, value in extra.items():
                self.assertEqual(restored[key], value)
            self.assertTrue(self.module.uri_preserves_clash_config(proxy, node['raw_uri']))

    def test_collision_suffixes_are_unique_in_yaml_and_generic_including_reserved_names(self):
        proxies = [{'name': name, 'type': 'trojan', 'server': 'example.com', 'port': 443 + i,
                    'password': 'fake'} for i, name in enumerate(['HK-01', 'HK-02', 'HK-01 [2]'])]
        self.account(proxies)
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO rename_rules(old_text,new_text) VALUES ('HK-02','HK-01')")
            db.commit()
        names = [p['name'] for p in yaml.safe_load(self.client.get('/sub/account?format=clash').data)['proxies']]
        self.assertEqual(names, ['HK-01', 'HK-01 [3]', 'HK-01 [2]'])
        lines = base64.b64decode(self.client.get('/sub/account').data).decode().splitlines()
        self.assertEqual([self.module.parse_protocol_uri(line, 'trojan')['name'] for line in lines], names)
        self.assertEqual(self.client.get('/api/subscribe').json['links'], lines)

    def test_dependencies_follow_renames_and_filtering_never_turns_them_into_direct_routes(self):
        proxies = [{'name': 'entry', 'type': 'trojan', 'server': 'example.com', 'port': 443, 'password': 'fake'},
                   {'name': 'exit', 'type': 'trojan', 'server': 'example.com', 'port': 444, 'password': 'fake', 'dialer-proxy': 'entry'}]
        self.account(proxies)
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute("INSERT INTO rename_rules(old_text,new_text) VALUES ('entry','renamed')")
            db.commit()
        output = yaml.safe_load(self.client.get('/sub/account?format=clash').data)['proxies']
        self.assertEqual(output[1]['dialer-proxy'], output[0]['name'])
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute('UPDATE node_filter SET enabled=1,keywords=?', (json.dumps(['entry']),))
            db.commit()
        self.assertEqual(yaml.safe_load(self.client.get('/sub/account?format=clash').data)['proxies'], [])
        self.assertIn('依赖不可用 1', self.client.get('/accounts/1').text)

    def test_cycles_are_not_exported(self):
        self.account([{'name': name, 'type': 'trojan', 'server': 'example.com', 'port': 443,
                       'password': 'fake', 'dialer-proxy': dependency}
                      for name, dependency in [('a', 'b'), ('b', 'a'), ('c', 'a')]])
        self.assertEqual(yaml.safe_load(self.client.get('/sub/account?format=clash').data)['proxies'], [])

    def test_batch_flushes_each_wave_before_fetching_more_and_preserves_failed_accounts(self):
        for i in range(9):
            self.account(name=str(i))
        original = self.module._bounded_parallel_map
        waves = []

        def bounded(function, items, max_workers=8):
            with sqlite3.connect(self.database) as db:
                waves.append((len(items), db.execute('SELECT COUNT(*) FROM accounts WHERE last_synced_at IS NOT NULL').fetchone()[0]))
            return original(function, items, max_workers)

        def fetch(url):
            if url.endswith('/8'):
                raise ValueError('upstream failed')
            return [self.module.parse_protocol_uri('trojan://fake@example.com:443#new', 'trojan')], {}

        with mock.patch.object(self.module, '_bounded_parallel_map', side_effect=bounded), mock.patch.object(self.module, 'parse_subscribe_url', side_effect=fetch):
            response = self.client.post('/api/sync-all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(waves, [(4, 0), (4, 4), (1, 8)])
        self.assertEqual(response.json['results'][-1]['status'], 'error')
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute('SELECT name FROM nodes WHERE account_id=9').fetchone()[0], 'one')

    @unittest.skipUnless(os.name == 'posix', 'tests POSIX production worker locks')
    def test_workers_share_a_lock_and_process_exit_releases_it(self):
        script = '''import sys
from test_app import load_app
m = load_app(sys.argv[1])
with m._bulk_operation_lock() as acquired:
 print(acquired, flush=True)
 sys.stdin.read()
'''
        worker = subprocess.Popen([sys.executable, '-c', script, str(self.database)],
                                  cwd=Path(__file__).parent, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(worker.stdout.readline().strip(), 'True')
            response = self.client.post('/api/sync-all')
            self.assertEqual(response.status_code, 409)
            worker.kill()
            worker.communicate(timeout=5)
            self.assertEqual(self.client.post('/api/sync-all').status_code, 200)
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.communicate(timeout=5)

    def test_suspended_account_and_maximum_expiry_have_consistent_working_pages(self):
        account_id = self.account()
        response = self.client.post('/services/add', data={
            'account_id': account_id, 'wechat_id': 'review-user', 'relationship': '自用',
            'started_on': '2020-01-01', 'expires_on': '9999-12-31'})
        self.assertEqual(response.status_code, 302)
        page = self.client.get('/services/1')
        self.assertEqual(page.status_code, 200)
        self.assertIn('已达日期上限', page.text)
        self.assertNotIn('id="renewModal"', page.text)
        with self.module.app.app_context():
            db = self.module.get_db()
            token = db.execute('SELECT sub_token FROM customer_services').fetchone()[0]
            db.execute("UPDATE accounts SET status='suspended'")
            db.commit()
        for url in ('/services', '/services/1', '/accounts/1'):
            page = self.client.get(url)
            self.assertEqual(page.status_code, 200)
            self.assertIn('专线未启用', page.text)
        self.assertEqual(self.client.get('/sub/' + token).status_code, 404)

    def test_local_times_handle_utc_offsets_and_invalid_values(self):
        formatter = self.module.format_local_datetime
        self.assertEqual(formatter('2026-09-24 01:02:03.456'), '2026-09-24 09:02:03')
        self.assertEqual(formatter('2026-09-24T09:02:03+08:00'), '2026-09-24 09:02:03')
        self.assertEqual(formatter(None), '')
        self.assertEqual(formatter('unknown'), 'unknown')

    def test_recursive_yaml_proxy_is_rejected(self):
        self.assertEqual(self.module._parse_clash_yaml('proxies: [ &p {name: a, type: trojan, server: example.com, port: 443, password: fake, x: *p}]'), [])

    def test_healthcheck_recovery_timeout_does_not_clear_failure_evidence(self):
        root = Path(self.temp.name)
        result = run_shell('deploy.sh', r'''
HEALTHCHECK_SCRIPT="$TEST_ROOT/healthcheck"
HEALTHCHECK_SERVICE="$TEST_ROOT/healthcheck.service"
HEALTHCHECK_TIMER="$TEST_ROOT/healthcheck.timer"
CADDY_RESTART_DROPIN="$TEST_ROOT/caddy/restart.conf"
PANEL_DOMAIN=panel.example.invalid
install() {
    local args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
write_keepalive_config
''', TEST_ROOT=root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('TimeoutStartSec=90s', (root / 'healthcheck.service').read_text())
        state = root / 'state'
        state.mkdir()
        (state / 'panel.failures').write_text('2\n')
        source = (root / 'healthcheck').read_text().replace('STATE_DIR=/run/anytls-panel-healthcheck', f'STATE_DIR={state}')
        fixtures = '''
install() { mkdir -p "$STATE_DIR"; }
logger() { :; }
flock() { return 0; }  # Lock behavior is covered by isolated Linux tests.
systemctl() { return 0; }
curl() { return 1; }
timeout() { [[ "$1" != 15 ]] || return 124; shift; "$@"; }
'''
        script = root / 'fixture'
        script.write_text(source.replace('set -u\n', 'set -u\n' + fixtures))
        result = subprocess.run(['bash', str(script)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((state / 'panel.failures').read_text().strip(), '3')
        self.assertTrue((state / 'panel.last_recovery').exists())
