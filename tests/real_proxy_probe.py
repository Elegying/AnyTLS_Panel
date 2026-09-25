#!/usr/bin/env python3
"""Real AnyTLS authentication over loopback; no production credentials or network."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy_verifier


def main(core):
    with tempfile.TemporaryDirectory(prefix='anytls-core-test-') as tmp:
        root = Path(tmp)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=15)
        os.environ['SSL_CERT_FILE'] = str(cert)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/ws':
                    target.ws_hosts.append(self.headers.get('Host'))
                    self.send_response(400)  # Capture the handshake, not a VMess server.
                    self.end_headers()
                    return
                # Mihomo rejects a zero-millisecond delay even after a successful request.
                # Keep fast loopback runners above the controller's timing resolution.
                time.sleep(0.02)
                self.send_response(target.response_status)
                self.end_headers()

            do_HEAD = do_GET

            def log_message(self, *_args):
                pass

        target = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        target.response_status = 204
        target.ws_hosts = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        thread = threading.Thread(target=target.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = {'log-level': 'silent', 'mode': 'rule', 'rules': ['MATCH,DIRECT'],
                  'listeners': [{'name': 'fixture', 'type': 'anytls', 'listen': '127.0.0.1', 'port': port,
                                 'users': {'fixture': 'correct-fixture'}, 'certificate': str(cert), 'private-key': str(key)}]}
        (root / 'server.json').write_text(json.dumps(config), encoding='utf-8')
        process = subprocess.Popen([core, '-d', tmp, '-f', str(root / 'server.json')],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline or process.poll() is not None:
                        raise RuntimeError('fixture core failed to start')
                    time.sleep(0.02)
            proxy_verifier.CORE_PATH = core
            proxy_verifier.PROBE_URL = f'https://127.0.0.1:{target.server_port}/generate_204'
            results = []
            pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            for status, password, fingerprint, expected in [(204, 'correct-fixture', pin, 'verified'),
                                                            (204, 'incorrect-fixture', pin, 'failed'),
                                                            (204, 'correct-fixture', '00' * 32, 'failed'),
                                                            (403, 'correct-fixture', pin, 'failed'),
                                                            (500, 'correct-fixture', pin, 'failed')]:
                target.response_status = status
                proxy = dict(name='fixture', type='anytls', server='localhost', port=port,
                             password=password, fingerprint=fingerprint, **{'skip-cert-verify': True})
                node = dict(protocol='anytls', host='localhost', port=port, password=password,
                            raw_uri=f'anytls://{password}@localhost:{port}?insecure=1', clash_config=json.dumps(proxy))
                result = proxy_verifier.verify_node_proxy(node, lambda *_: ['127.0.0.1'], tmp,
                                                         timeout=6, allow_private=True)
                assert result['status'] == expected, (expected, result)
                assert not list(root.glob('probe-*')), 'probe configuration was not cleaned'
                results.append({'case': len(results)+1, 'target_http_status': status, 'status': result['status']})
            for headers, expected_host in (({}, 'localhost'), ({'Host': 'front.example'}, 'front.example')):
                target.ws_hosts.clear()
                proxy = dict(type='vmess', server='localhost', port=target.server_port,
                             uuid='00000000-0000-4000-8000-000000000001', alterId=0,
                             cipher='auto', network='ws', tls=True, servername='localhost',
                             **{'ws-opts': {'path': '/ws', 'headers': headers}})
                node = dict(protocol='vmess', host='localhost', port=target.server_port,
                            raw_uri='', clash_config=json.dumps(proxy))
                result = proxy_verifier.verify_node_proxy(node, lambda *_: ['127.0.0.1'], tmp,
                                                         timeout=6, allow_private=True)
                assert target.ws_hosts == [expected_host], target.ws_hosts
                assert result['status'] == 'failed', result  # Fixture rejects the upgrade.
                assert not list(root.glob('probe-*')), 'probe configuration was not cleaned'
                results.append({'case': 'websocket_host', 'explicit': bool(headers), 'preserved': True})
            print(json.dumps({'real_core': True, 'loopback_only': True, 'results': results}))
        finally:
            process.terminate()
            process.wait(timeout=5)
            target.shutdown()
            target.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    main(str(Path(sys.argv[1]).resolve()))
