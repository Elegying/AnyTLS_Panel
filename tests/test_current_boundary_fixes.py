"""Current network, accounting and protocol boundary regressions."""
import os
import socket
import ssl
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import yaml
from test_app import authenticate_session, load_app


class CurrentBoundaryFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = mock.patch.dict(os.environ, {
            'ANYTLS_SECRET_KEY_FILE': str(self.root / 'secret'),
            'ANYTLS_TRAFFIC_API_TOKEN_FILE': str(self.root / 'traffic'),
            'ANYTLS_ADMIN_PASSWORD_FILE': str(self.root / 'admin'),
        })
        env.start()
        self.addCleanup(env.stop)
        self.panel = load_app(self.root / 'panel.db')
        self.panel.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.panel.app.test_client()
        authenticate_session(self.panel, self.client)
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute("INSERT INTO accounts(name,subscribe_url) VALUES ('fixture','fixture')")
            db.commit()
            self.headers = {'Authorization': 'Bearer ' + self.panel.get_traffic_api_token()}

    def send(self, counter, seq=None):
        payload = dict(collector_id='fixture-collector', account_id=1, counter_bytes=counter)
        if seq is not None:
            payload['sample_seq'] = seq
        return self.client.post('/api/traffic/counter', json=payload, headers=self.headers)

    def test_delayed_samples_retries_and_real_reset(self):
        self.assertEqual(self.send(1000, 1).json['delta_bytes'], 0)
        self.assertEqual(self.send(1200, 3).json['delta_bytes'], 200)
        self.assertEqual(self.send(1100, 2).status_code, 409)
        self.assertEqual(self.send(1200, 3).json['delta_bytes'], 0)
        self.assertEqual(self.send(1300, 3).status_code, 409)
        self.assertEqual(self.send(1300).status_code, 409)
        reset = self.send(20, 4)
        self.assertEqual(reset.json['delta_bytes'], 20)
        self.assertEqual(reset.json['total_bytes'], 220)
        with self.panel.app.app_context():
            row = self.panel.get_db().execute('SELECT * FROM traffic_collectors').fetchone()
            self.assertEqual((row['last_counter_bytes'], row['last_sample_seq']), (20, 4))

    def test_legacy_monotonic_upgrade_and_sequence_validation(self):
        self.send(1000)
        self.assertEqual(self.send(1200).json['delta_bytes'], 200)
        self.assertEqual(self.send(1100).status_code, 409)
        self.assertEqual(self.send(1200).json['delta_bytes'], 0)
        for invalid in (0, -1, True, 1.5, '2', [], 9223372036854775808):
            with self.subTest(seq=invalid):
                self.assertEqual(self.send(1300, invalid).status_code, 400)
        self.assertEqual(self.send(1300, 1).json['total_bytes'], 300)

    def test_concurrent_duplicate_sample_is_counted_once(self):
        self.send(1000, 1)
        def send_duplicate(_):
            with self.panel.app.test_client() as client:
                return client.post('/api/traffic/counter', headers=self.headers,
                                   json=dict(account_id=1, collector_id='fixture-collector',
                                             counter_bytes=1200, sample_seq=2))
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(send_duplicate, range(4)))
        self.assertTrue(all(r.status_code == 200 for r in responses))
        self.assertEqual(sum(r.json['delta_bytes'] for r in responses), 200)
        self.assertTrue(all(r.json['total_bytes'] == 200 for r in responses))

    def test_schema_upgrade_preserves_existing_baseline(self):
        self.send(1000)
        with self.panel.app.app_context():
            db = self.panel.get_db()
            db.execute('ALTER TABLE traffic_collectors DROP COLUMN last_sample_seq')
            db.execute('DELETE FROM schema_migrations WHERE version=9')
            db.commit()
        self.panel.init_db()
        self.panel.init_db()
        self.assertEqual(self.send(1200, 1).json['total_bytes'], 200)

    def test_trickling_headers_and_chunk_framing_obey_deadline(self):
        for initial in (
            b'HTTP/1.1 200 OK\r\nX-Fixture: ',
            b'HTTP/1.1 200',
            b'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nX-Fixture: ',
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;fixture=',
            b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nanytls://fixture@node.example:443#fixture\n',
        ):
            with self.subTest(initial=initial):
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                port = listener.getsockname()[1]
                def serve():
                    with listener:
                        conn, _ = listener.accept()
                        with conn:
                            conn.recv(8192)
                            try:
                                conn.sendall(initial)
                                for _ in range(60):
                                    time.sleep(0.025)
                                    conn.sendall(b'a')
                            except OSError:
                                pass
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                started = time.monotonic()
                with mock.patch.object(self.panel, '_resolve_public_subscription_url',
                                       return_value=(urlparse(f'http://fixture.example:{port}/'), ['127.0.0.1'])):
                    with self.assertRaises(OSError):
                        self.panel._read_pinned_subscription_response(
                            f'http://fixture.example:{port}/', 'fixture', deadline=started + 0.2)
                self.assertLess(time.monotonic() - started, 0.7)
                thread.join(2)
                self.assertFalse(thread.is_alive())

    def test_transport_options_survive_import_and_public_clash_export(self):
        for protocol in ('vless', 'trojan'):
            for network in ('h2', 'http'):
                uri = (f'{protocol}://00000000-0000-4000-8000-000000000001@node.example:443'
                       f'?security=tls&type={network}&host=front.example,other.example&path=%2Ftunnel#fixture')
                response = self.client.post('/accounts/add', data={'name': 'fixture', 'subscribe_url': uri})
                self.assertEqual(response.status_code, 302)
                with self.panel.app.app_context():
                    aid = self.panel.get_db().execute('SELECT MAX(id) FROM accounts').fetchone()[0]
                token = self.client.post(f'/api/accounts/{aid}/generate-token').json['token']
                exported = self.client.get('/sub/' + token + '?format=clash')
                self.assertEqual(exported.status_code, 200)
                proxy = yaml.safe_load(exported.data)['proxies'][0]
                if network == 'h2':
                    self.assertEqual(proxy['h2-opts'], {'host': ['front.example', 'other.example'], 'path': '/tunnel'})
                else:
                    self.assertEqual(proxy['http-opts'], {'method': 'GET', 'path': ['/tunnel'],
                                                       'headers': {'Host': ['front.example', 'other.example']}})

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed for a trusted local TLS fixture')
    def test_https_trickling_headers_terminate_without_weakening_tls(self):
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=fixture.example', '-addext', 'subjectAltName=DNS:fixture.example'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        client_context = ssl.create_default_context(cafile=str(cert))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        def serve():
            with listener:
                conn, _ = listener.accept()
                with server_context.wrap_socket(conn, server_side=True) as secured:
                    secured.recv(8192)
                    try:
                        secured.sendall(b'HTTP/1.1 200 OK\r\nX-Fixture: ')
                        for _ in range(60):
                            time.sleep(0.025)
                            secured.sendall(b'a')
                    except OSError:
                        pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = time.monotonic()
        with mock.patch.object(self.panel, '_resolve_public_subscription_url',
                               return_value=(urlparse(f'https://fixture.example:{port}/'), ['127.0.0.1'])), \
                mock.patch.object(self.panel.ssl, 'create_default_context', return_value=client_context):
            with self.assertRaises(OSError):
                self.panel._read_pinned_subscription_response(
                    f'https://fixture.example:{port}/', 'fixture', deadline=started + 0.35)
        self.assertLess(time.monotonic() - started, 0.9)
        self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client_context.check_hostname)
        thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_collector_sequence_persists_across_processes_and_refuses_symlink(self):
        script = Path(__file__).resolve().parents[1] / 'traffic_collector.sh'
        source = f'''source "{script}"
COLLECTOR_ID_FILE="$FIXTURE_ROOT/collector.id"
validate_collector_path_parent() {{ :; }}
reserve_sample_sequence || exit
printf '%s\\n' "$SAMPLE_SEQ"
'''
        for expected in ('1', '2'):
            result = subprocess.run(['bash', '-c', source], env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.strip(), expected)
        sequence = self.root / 'collector.id.sequence'
        self.assertEqual(sequence.stat().st_mode & 0o777, 0o600)
        sequence.unlink()
        sequence.symlink_to(self.root / 'absent')
        result = subprocess.run(['bash', '-c', source], env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'absent').exists())

    def test_sequence_failure_does_not_send_and_maximum_does_not_wrap(self):
        script = Path(__file__).resolve().parents[1] / 'traffic_collector.sh'
        prefix = f'''source "{script}"
COLLECTOR_ID_FILE="$FIXTURE_ROOT/collector.id"
validate_collector_path_parent() {{ :; }}
'''
        sequence = self.root / 'collector.id.sequence'
        for value in ('invalid', '9223372036854775807', '9999999999999999999'):
            sequence.write_text(value + '\n')
            result = subprocess.run(['bash', '-c', prefix + 'reserve_sample_sequence'],
                                    env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sequence.read_text(), value + '\n')
        sequence.write_text('9223372036854775806\n')
        result = subprocess.run(['bash', '-c', prefix + "reserve_sample_sequence && printf '%s' \"$SAMPLE_SEQ\""],
                                env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, '9223372036854775807')
        sequence.unlink()
        sequence.mkdir()
        source = prefix + '''
validate_configuration() { :; }
acquire_collector_lock() { :; }
ensure_collector_id() { :; }
ensure_iptables() { :; }
get_traffic_bytes() { printf '25\\n'; }
report_traffic() { printf 'unexpected-send'; }
main
'''
        result = subprocess.run(['bash', '-c', source], env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected-send', result.stdout)

    def test_stale_temp_file_does_not_block_sequence_after_pid_reuse(self):
        script = Path(__file__).resolve().parents[1] / 'traffic_collector.sh'
        source = f'''source "{script}"
COLLECTOR_ID_FILE="$FIXTURE_ROOT/collector.id"
validate_collector_path_parent() {{ :; }}
printf 'stale\\n' > "${{COLLECTOR_ID_FILE}}.sequence.tmp.$$"
reserve_sample_sequence || exit
printf '%s\\n' "$SAMPLE_SEQ"
'''
        result = subprocess.run(['bash', '-c', source], env={**os.environ, 'FIXTURE_ROOT': str(self.root)},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '1')
