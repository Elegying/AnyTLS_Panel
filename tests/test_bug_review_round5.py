"""VMess transport and TLS configuration preservation regressions."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

import node_probe
import protocol_codecs
import proxy_verifier
from test_app import authenticate_session, load_app


def vmess_uri(**changes):
    payload = dict(v='2', ps='fixture', add='fixture.example', port='443',
                   id='00000000-0000-4000-8000-000000000001', net='tcp', tls='tls')
    payload.update(changes)
    return 'vmess://' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')


class ReviewRoundFive(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.panel = load_app(self.root / 'panel.db')
        self.panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.panel.app.test_client()
        authenticate_session(self.panel, self.client)

    def test_standard_vmess_transports_survive_conversion_and_yaml_export(self):
        cases = [
            ({'net': 'grpc', 'path': 'fixture-service'}, 'grpc', {'grpc-opts': {'grpc-service-name': 'fixture-service'}}),
            ({'net': 'grpc', 'serviceName': 'legacy-service'}, 'grpc', {'grpc-opts': {'grpc-service-name': 'legacy-service'}}),
            ({'net': 'h2', 'host': 'cover.example,other.example', 'path': '/tunnel'}, 'h2',
             {'h2-opts': {'host': ['cover.example', 'other.example'], 'path': '/tunnel'}}),
            ({'net': 'tcp', 'type': 'http', 'host': 'cover.example,other.example', 'path': '/a,/b'}, 'http',
             {'http-opts': {'method': 'GET', 'headers': {'Host': ['cover.example', 'other.example']}, 'path': ['/a', '/b']}}),
        ]
        for changes, network, expected in cases:
            with self.subTest(network=network, changes=changes):
                uri = vmess_uri(**changes)
                proxy = protocol_codecs.clash_proxy_from_uri(uri)
                self.assertEqual(proxy.get('network'), network)
                for key, value in expected.items():
                    self.assertEqual(proxy.get(key), value)
                response = self.client.post('/accounts/add', data={'name': 'fixture', 'subscribe_url': uri})
                self.assertEqual(response.status_code, 302)
                account_id = int(response.location.rsplit('/', 1)[1])
                with self.panel.app.app_context():
                    db = self.panel.get_db()
                    db.execute('UPDATE accounts SET sub_token=? WHERE id=?', (f'fixture-{account_id}', account_id))
                    db.commit()
                exported = self.client.get(f'/sub/fixture-{account_id}?format=clash')
                self.assertEqual(exported.status_code, 200)
                self.assertEqual(yaml.safe_load(exported.data)['proxies'][0], proxy)
                node = protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]
                self.assertTrue(protocol_codecs.uri_preserves_clash_config(proxy, node['raw_uri']))
                for key, value in expected.items():
                    self.assertEqual(protocol_codecs.clash_proxy_from_uri(node['raw_uri'])[key], value)

    def test_standard_insecure_flag_is_consistent_with_entry_probe(self):
        for flag in ('0', '1', False, True):
            uri = vmess_uri(insecure=flag)
            proxy = protocol_codecs.clash_proxy_from_uri(uri)
            node = protocol_codecs.parse_protocol_uri(uri, 'vmess')
            expected = flag in ('1', True)
            self.assertEqual(proxy.get('skip-cert-verify', False), expected)
            self.assertEqual(node_probe.probe_options(node)['insecure'], expected)

    def test_vmess_certificate_constraints_reach_exports_and_core(self):
        uri = vmess_uri(pcs='A1' * 32, vcn='certificate.fixture.example',
                        sni='sni.fixture.example', insecure='1', fp='chrome')
        proxy = protocol_codecs.clash_proxy_from_uri(uri)
        self.assertEqual(proxy.get('fingerprint'), 'A1' * 32)
        self.assertEqual(proxy.get('name-cert-verify'), 'certificate.fixture.example')
        self.assertEqual(proxy['client-fingerprint'], 'chrome')
        node = protocol_codecs.parse_protocol_uri(uri, 'vmess')
        with mock.patch.object(node_probe.socket, 'create_connection', side_effect=OSError), \
                mock.patch.object(proxy_verifier, 'run_core', return_value=10) as core:
            result = proxy_verifier.verify_node_proxy(node, lambda *_: ['8.8.8.8'], self.root)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(result['tls_mode'], 'pinned')
        self.assertEqual(core.call_args.args[0]['fingerprint'], 'A1' * 32)
        self.assertEqual(core.call_args.args[0]['name-cert-verify'], 'certificate.fixture.example')
        canonical = protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]
        self.assertTrue(protocol_codecs.uri_preserves_clash_config(proxy, canonical['raw_uri']))

    def test_entry_probe_does_not_claim_certificate_constraints_it_cannot_check(self):
        for extra in ({'pcs': 'A1' * 32}, {'vcn': 'certificate.fixture.example'}):
            node = protocol_codecs.parse_protocol_uri(vmess_uri(**extra), 'vmess')
            self.assertEqual(node_probe.probe_options(node)['tls'], 'unsupported')

    def test_vmess_port_rejects_boolean_and_fractional_values(self):
        for port in (True, False, 443.5, [], {}, 0, 65536):
            with self.subTest(port=port):
                self.assertIsNone(protocol_codecs.parse_protocol_uri(vmess_uri(port=port), 'vmess'))
        for port in ('443', 443):
            self.assertEqual(protocol_codecs.parse_protocol_uri(vmess_uri(port=port), 'vmess')['port'], 443)

    def test_malformed_transport_options_do_not_break_other_subscription_nodes(self):
        for field in ('net', 'type', 'host', 'path', 'serviceName', 'vcn', 'pcs'):
            for value in ([], {}, True):
                with self.subTest(field=field, value=value):
                    self.assertIsNone(protocol_codecs.parse_protocol_uri(vmess_uri(**{field: value}), 'vmess'))
        self.assertIsNotNone(protocol_codecs.parse_protocol_uri(vmess_uri(net='grpc', path=None, host=None), 'vmess'))
        good = dict(name='valid', type='vmess', server='fixture.example', port=443,
                    uuid='00000000-0000-4000-8000-000000000001')
        for network, field, value in (('h2', 'h2-opts', ['bad']),
                                      ('http', 'http-opts', ['bad']),
                                      ('http', 'http-opts', {'headers': ['bad']})):
            source = yaml.safe_dump({'proxies': [dict(good, network=network, **{field: value}), good]})
            nodes = protocol_codecs.parse_clash_yaml(source)
            self.assertEqual([node['name'] for node in nodes], ['valid'])

    def test_advanced_http_settings_still_require_lossless_yaml_output(self):
        proxy = dict(name='fixture', type='vmess', server='fixture.example', port=443,
                     uuid='00000000-0000-4000-8000-000000000001', network='http',
                     **{'http-opts': {'method': 'POST', 'path': ['/tunnel'], 'headers': {'Host': ['cover.example']}}})
        node = protocol_codecs.parse_clash_yaml(yaml.safe_dump({'proxies': [proxy]}))[0]
        self.assertFalse(protocol_codecs.uri_preserves_clash_config(proxy, node['raw_uri']))
        with self.panel.app.app_context():
            db = self.panel.get_db()
            account_id = db.execute("INSERT INTO accounts(name, subscribe_url, sub_token) VALUES ('fixture','fixture','fixture-token')").lastrowid
            self.panel._replace_account_nodes(db, account_id, [node])
            db.commit()
        self.assertEqual(self.client.get('/sub/fixture-token?format=base64').status_code, 406)
        self.assertEqual(yaml.safe_load(self.client.get('/sub/fixture-token?format=clash').data)['proxies'], [proxy])
