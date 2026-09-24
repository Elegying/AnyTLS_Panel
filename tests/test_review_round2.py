"""Regression cases from the independent second review (synthetic inputs only)."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from test_app import load_app, authenticate_session
import test_audit_fixes
import protocol_codecs
import subscription_export
from test_reliability import run_shell


class SecondReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / 'panel.db'
        self.module = load_app(self.database)
        self.module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.module.app.test_client()
        authenticate_session(self.module, self.client)

    account = test_audit_fixes.AuditFixTests.account

    def test_certificate_pin_never_becomes_a_client_fingerprint(self):
        for i, extra in enumerate(({'fingerprint': 'A1' * 32},
                                   {'fingerprint': 'B2' * 32, 'client-fingerprint': 'chrome'})):
            proxy = dict(name='pinned', type='trojan', server='example.com', port=443,
                         password='fake', **{'skip-cert-verify': True}, **extra)
            self.account([proxy], name=str(i))
            uri = protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]['raw_uri']
            self.assertFalse(protocol_codecs.uri_preserves_clash_config(proxy, uri))
            self.assertEqual(self.client.get('/sub/' + str(i) + '?format=base64').status_code, 406)
            for agent in ('SSRVPN/4', 'Mihomo/1'):
                response = self.client.get('/sub/' + str(i), headers={'User-Agent': agent})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(yaml.safe_load(response.data)['proxies'], [proxy])

    def test_required_protocol_fields_and_types_are_checked(self):
        for protocol, fields in [('trojan', {'password': 'fake'}),
                                 ('anytls', {'password': 'fake'}),
                                 ('vless', {'uuid': 'test-uuid'}),
                                 ('vmess', {'uuid': 'test-uuid'}),
                                 ('tuic', {'uuid': 'test-uuid', 'password': 'fake'}),
                                 ('ss', {'cipher': 'aes-128-gcm', 'password': 'fake'})]:
            valid = dict(type=protocol, name='valid', server='example.com', port=443, **fields)
            self.assertEqual(len(protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [valid]}))), 1)
            for field in fields:
                for bad in (None, '', [], True, 123):
                    invalid = {**valid, field: bad}
                    self.assertEqual(protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [invalid]})), [])
        for uri in ('vless://@example.com:443', 'trojan://@example.com:443', 'tuic://uuid@example.com:443'):
            self.assertIsNone(protocol_codecs.clash_proxy_from_uri(uri))

    def test_invalid_sync_retains_good_cache_and_reports_failure(self):
        aid = self.account()
        source = yaml.safe_dump({'proxies': [dict(type='vless', name='invalid', server='example.com', port=443)]})
        with self.module.app.app_context():
            db = self.module.get_db()
            db.execute('UPDATE accounts SET subscribe_url=? WHERE id=?', (source, aid))
            db.commit()
        self.client.post(f'/accounts/{aid}/sync')
        response = self.client.post('/api/sync-all')
        self.assertEqual(response.json['results'][0]['status'], 'error')
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute('SELECT name FROM nodes').fetchone()[0], 'one')

    def test_reserved_names_and_generated_suffixes_are_unique_in_all_exports(self):
        names = ['DIRECT', 'DIRECT [2]', 'REJECT', 'GLOBAL', 'PASS', 'normal']
        self.account([dict(name=n, type='trojan', server='example.com', port=443, password='fake') for n in names])
        proxies = yaml.safe_load(self.client.get('/sub/account?format=clash').data)['proxies']
        exported = [p['name'] for p in proxies]
        self.assertEqual(len(set(exported)), len(names))
        self.assertFalse(set(exported) & subscription_export.RESERVED_NAMES)
        self.assertEqual(exported[:2], ['DIRECT [3]', 'DIRECT [2]'])
        links = self.client.get('/api/subscribe').json['links']
        self.assertEqual([protocol_codecs.parse_protocol_uri(u, 'trojan')['name'] for u in links], exported)

    def test_rename_expansion_is_rejected_before_save_and_legacy_rules_fail_closed(self):
        self.account([dict(name='A', type='trojan', server='example.com', port=443, password='fake')])
        rule = {'old_text': 'A', 'new_text': 'A' * 100}
        self.client.post('/settings/rename-rules/add', data=rule)
        response = self.client.post('/settings/rename-rules/add', data=rule, follow_redirects=True)
        self.assertIn('不能超过 512', response.text)
        with self.module.app.app_context():
            db = self.module.get_db()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rename_rules').fetchone()[0], 1)
            db.execute('INSERT INTO rename_rules(old_text,new_text) VALUES (?,?)', tuple(rule.values()))
            db.commit()
        self.assertEqual(self.client.get('/sub/account').status_code, 503)
        self.assertEqual(self.client.get('/api/subscribe').status_code, 422)
        page = self.client.get('/accounts/1')
        self.assertEqual(page.status_code, 200)
        self.assertIn('订阅生成失败', page.text)
        self.client.post('/settings/rename-rules/2/toggle')  # disabling must permit recovery
        self.assertEqual(self.client.get('/sub/account').status_code, 200)
        self.client.post('/settings/rename-rules/2/toggle')  # enabling invalid rules is rejected
        self.assertEqual(self.client.get('/sub/account').status_code, 200)

    def test_rule_count_and_total_output_are_bounded(self):
        self.account()
        with self.module.app.app_context():
            db = self.module.get_db()
            db.executemany('INSERT INTO rename_rules(old_text,new_text,enabled) VALUES (?,?,0)', [('a', 'b')] * 100)
            db.commit()
        self.client.post('/settings/rename-rules/add', data={'old_text': 'x', 'new_text': 'y'})
        with self.module.app.app_context():
            self.assertEqual(self.module.get_db().execute('SELECT COUNT(*) FROM rename_rules').fetchone()[0], 100)
        with mock.patch.object(subscription_export, 'MAX_EXPORT_BYTES', 64):
            self.assertEqual(self.client.get('/sub/account').status_code, 503)

    def test_sync_audit_distinguishes_failure_partial_and_success(self):
        self.account(name='one')
        self.account(name='two')
        good = [self.module.parse_protocol_uri('trojan://fake@example.com:443#valid', 'trojan')]
        for values, outcome, counts in [([ValueError('invalid'), ValueError('invalid')], 'failure', (0, 2)),
                                        ([(good, {}), ValueError('invalid')], 'partial', (1, 1)),
                                        ([(good, {}), (good, {})], 'success', (2, 0))]:
            with mock.patch.object(self.module, 'parse_subscribe_url', side_effect=values), mock.patch.object(self.module, 'audit_event') as event:
                self.client.post('/api/sync-all')
                self.assertEqual(event.call_args.args[:2], ('account.sync_all', outcome))
                self.assertEqual((event.call_args.kwargs['succeeded'], event.call_args.kwargs['failed']), counts)
        with mock.patch.object(self.module.audit_logger, 'info') as logger:
            self.module.audit_event('account.sync_all', 'failure', failed=2, succeeded=0, skipped=0)
            payload = json.loads(logger.call_args.args[1])
            self.assertEqual(payload['failed'], 2)
            self.assertIn('occurred_at', payload)

    def test_nonobject_json_is_a_client_error(self):
        for data in (['host'], 'text', 1, True, None, []):
            self.assertEqual(self.client.post('/api/check-by-host', json=data).status_code, 400)

    def test_release_verifier_rejects_bad_hash_and_bad_signature(self):
        result = run_shell('install-release.sh', r'''
archive="$TEST_ROOT/AnyTLS_Panel-v1.2.3.tar.gz"
printf 'fixture' > "$archive"
sha256sum "$archive" | sed "s|$TEST_ROOT/||" > "$archive.sha256"
COSIGN=fixture-cosign
calls=0
timeout() { ((calls+=1)); [[ "$*" == *'refs/tags/v1.2.3'* && "$*" == *'https://token.actions.githubusercontent.com'* ]]; }
verify_release "$archive" v1.2.3
[[ "$calls" -eq 1 ]]
timeout() { return 1; }
if verify_release "$archive" v1.2.3; then exit 80; fi
printf 'tampered' >> "$archive"
timeout() { exit 81; }
if verify_release "$archive" v1.2.3; then exit 82; fi
''', TEST_ROOT=self.temp.name)
        self.assertEqual(result.returncode, 0, result.stderr)
