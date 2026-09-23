"""Exercise the generated Caddy protection against real incomplete HTTP bodies.

Run with the application's virtualenv Python and an installed Caddy >= 2.11.4.
All state, servers and ports are disposable and local to this process.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    backend, edge = port(), port()
    caddy = shutil.which('caddy')
    assert caddy, 'Caddy must be on PATH'
    with tempfile.TemporaryDirectory(prefix='anytls-edge-regression-') as temp:
        directory = Path(temp)
        env = dict(os.environ, ANYTLS_DATABASE=str(directory / 'db'),
                   ANYTLS_SECRET_KEY_FILE=str(directory / 'secret'),
                   ANYTLS_TRAFFIC_API_TOKEN_FILE=str(directory / 'traffic'),
                   ANYTLS_ADMIN_PASSWORD_FILE=str(directory / 'initial'),
                   XDG_CONFIG_HOME=str(directory / 'config'), XDG_DATA_HOME=str(directory / 'data'),
                   TEST_DIR=temp, ANYTLS_PANEL_PORT=str(backend), ANYTLS_PANEL_DOMAIN='localhost')
        # Include a pre-existing global block to cover safe insertion and idempotency.
        shell = r'''source "$1" --help
CADDY_CONFIG_DIR="$TEST_DIR"
CADDYFILE="$TEST_DIR/Caddyfile"
printf '{\n admin off\n auto_https off\n}\n' > "$CADDYFILE"
render_caddy_site >> "$CADDYFILE"
sed -i "s/^localhost {/http:\/\/localhost:$2 {/" "$CADDYFILE"
caddy fmt --overwrite "$CADDYFILE" >/dev/null
ensure_caddy_request_deadlines
caddy fmt --overwrite "$CADDYFILE" >/dev/null
ensure_caddy_request_deadlines
caddy validate --config "$CADDYFILE"
'''
        prepared = subprocess.run(['bash', '-c', shell, '_', str(ROOT / 'deploy.sh'), str(edge)],
                                  env=env, capture_output=True, text=True, timeout=15)
        assert prepared.returncode == 0, prepared.stderr
        configuration = directory / 'Caddyfile'
        assert configuration.read_text().count('read_body') == 1
        config = json.loads(subprocess.check_output([caddy, 'adapt', '--config', str(configuration)], stderr=subprocess.DEVNULL))
        servers = config['apps']['http']['servers']
        assert all(s['read_timeout'] == 30_000_000_000 for s in servers.values())
        assert all(s['read_header_timeout'] == 10_000_000_000 for s in servers.values())
        # Accelerate the same configured deadline for the regression, after checking production values.
        configuration.write_text(configuration.read_text().replace('read_body 30s', 'read_body 5s'))
        processes, sockets = [], []
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def get(path, target=edge):
            with opener.open(f'http://localhost:{target}{path}', timeout=2) as response:
                body = response.read()
                assert b'<form' in body if path == '/login' else b'"status"' in body
                return response.status

        with (directory / 'server.log').open('w+') as log:
            try:
                processes.append(subprocess.Popen([sys.executable, '-m', 'gunicorn', '--workers', '1', '--threads', '4',
                    '--timeout', '3', '--no-control-socket', '--bind', f'127.0.0.1:{backend}', 'app:create_app()'],
                    cwd=ROOT, env=env, stdout=log, stderr=log))
                processes.append(subprocess.Popen([caddy, 'run', '--config', str(configuration)], env=env, stdout=log, stderr=log))
                for _ in range(100):
                    try:
                        if get('/login') == 200:
                            break
                    except (OSError, urllib.error.URLError):
                        time.sleep(.1)
                else:
                    log.seek(0)
                    raise AssertionError(log.read())
                started = time.monotonic()
                for index in range(8):
                    sock = socket.create_connection(('127.0.0.1', edge), timeout=2)
                    sock.settimeout(7)
                    framing = (b'Content-Length: 65536\r\n\r\nx=slow' if index < 4 else
                               b'Transfer-Encoding: chunked\r\n\r\n10000\r\nx=slow')
                    sock.sendall(f'POST /login HTTP/1.1\r\nHost: localhost:{edge}\r\nConnection: close\r\n'.encode() + framing)
                    sockets.append(sock)
                time.sleep(.3)
                assert get('/login') == 200
                assert get('/readyz', backend) == 200
                request = urllib.request.Request(f'http://localhost:{edge}/login', data=b'x=' + b'a' * (1024 * 1024))
                try:
                    opener.open(request, timeout=3)
                except urllib.error.HTTPError as error:
                    assert error.code == 400  # Application CSRF response proves a complete body reached WSGI.
                for sock in sockets:
                    response = sock.recv(4096)
                    # Caddy 2.11 can close a timed-out read with an empty 200.
                    # It must not forward the incomplete form to the application.
                    assert not response or any(code in response for code in (b' 400 ', b' 502 ', b' 408 ')) or (
                        b' 200 ' in response and b'Content-Length: 0' in response), response[:100]
                assert time.monotonic() - started < 8
                oversize_statuses = []
                for chunked in (False, True):
                    with socket.create_connection(('127.0.0.1', edge), timeout=3) as sock:
                        framing = ('Transfer-Encoding: chunked' if chunked else 'Content-Length: 4194305')
                        sock.sendall(f'POST /login HTTP/1.1\r\nHost: localhost:{edge}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n{framing}\r\n\r\n'.encode())
                        payload = b'x' * 4194305
                        try:
                            sock.sendall(b'400001\r\n' + payload + b'\r\n0\r\n\r\n' if chunked else payload)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        response = sock.recv(4096)
                        status = int(response.split(b' ', 2)[1])
                        # Chunked forwarding can report an interrupted body as 400.
                        assert status == 413 or (chunked and status == 400), response[:100]
                        oversize_statuses.append(status)
                assert get('/login') == 200
                print(json.dumps({'slow_requests': 8, 'content_length_and_chunked': True,
                      'login_and_readiness_during_upload': 200, 'one_MiB_form_reaches_app': True,
                      'read_deadline_enforced': True, 'oversize_rejected': oversize_statuses}))
            finally:
                for sock in sockets:
                    sock.close()
                for process in processes:
                    process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == '__main__':
    main()
