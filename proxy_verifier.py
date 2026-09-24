"""Isolated Mihomo probes with pinned endpoints, private sockets and bounded lifetime."""
from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlencode

from node_probe import check_node_connect, _validated_addresses
from protocol_codecs import clash_proxy_from_uri

CORE_PATH = '/usr/local/lib/anytls-tools/mihomo-v1.19.31'
PROBE_URL = 'https://www.gstatic.com/generate_204'


def core_available():
    return os.name == 'posix' and os.path.isfile(CORE_PATH) and os.access(CORE_PATH, os.X_OK)


@contextmanager
def core_slot(directory):
    import fcntl
    handle = None
    for index in range(2):
        candidate = open(Path(directory) / f'.core-probe-{index}.lock', 'a+b')
        try:
            fcntl.flock(candidate.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            handle = candidate
            break
        except BlockingIOError:
            candidate.close()
    try:
        yield handle is not None
    finally:
        if handle:
            handle.close()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def wait_for_proxy(controller, process, deadline):
    # The control socket is opened before Mihomo finishes applying its proxies.
    # Waiting for the named proxy avoids treating startup as a node failure.
    while process.poll() is None and time.monotonic() < deadline:
        conn = UnixHTTPConnection(controller, min(0.5, max(0.01, deadline - time.monotonic())))
        try:
            conn.request('GET', '/proxies/health-probe')
            response = conn.getresponse()
            body = response.read(4097)
            if response.status == 200 and len(body) <= 4096 and json.loads(body).get('name') == 'health-probe':
                return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            conn.close()
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    raise RuntimeError('core unavailable')


def run_core(proxy, directory, deadline):
    with tempfile.TemporaryDirectory(prefix='probe-', dir=directory) as temporary:
        path = Path(temporary)
        controller = str(path / 'control.sock')
        # No listening proxy port, TUN, providers, downloads or direct fallback.
        config = {'mode': 'rule', 'log-level': 'silent', 'mixed-port': 0,
                  'external-controller-unix': controller, 'external-controller': '',
                  'dns': {'enable': False}, 'profile': {'store-selected': False},
                  'proxies': [proxy], 'rules': ['MATCH,REJECT'], 'geo-auto-update': False}
        (path / 'config.json').write_text(json.dumps(config), encoding='utf-8')
        process = subprocess.Popen(['/usr/bin/timeout', '--kill-after=1',
                                    str(max(0.1, deadline - time.monotonic())),
                                    CORE_PATH, '-d', temporary, '-f', str(path / 'config.json')],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        try:
            wait_for_proxy(controller, process, deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn = UnixHTTPConnection(controller, remaining)
            try:
                query = urlencode({'url': PROBE_URL, 'timeout': max(1, int(remaining * 1000)), 'expected': '204'})
                conn.request('GET', '/proxies/health-probe/delay?' + query)
                response = conn.getresponse()
                body = response.read(4097)
                if response.status != 200 or len(body) > 4096:
                    raise OSError('proxy access failed')
                delay = json.loads(body).get('delay')
                if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 0:
                    raise ValueError('invalid probe response')
                return delay
            finally:
                conn.close()
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=1)


def verify_node_proxy(node, resolver, directory, timeout=8, allow_private=False):
    deadline = time.monotonic() + timeout
    addresses = []

    def resolve(host, port, resolver_deadline):
        addresses[:] = _validated_addresses(resolver(host, port, resolver_deadline), allow_private)
        return addresses

    result = check_node_connect(node['host'], node['port'], min(3, timeout), resolve,
                                allow_private=allow_private, node=node)
    if not addresses:
        return result
    proxy = json.loads(node['clash_config']) if node.get('clash_config') else clash_proxy_from_uri(node['raw_uri'])
    if (not proxy or proxy.get('type') not in ('trojan', 'anytls', 'ss', 'vmess', 'vless', 'tuic', 'hysteria2')
            or proxy.get('dialer-proxy') not in (None, '', 'DIRECT')):
        result['msg'] = '已执行入口检查；此协议或链式代理暂不支持独立认证检测'
        return result
    proxy.pop('dialer-proxy', None)
    original_host = proxy['server']
    proxy['server'], proxy['name'] = addresses[0], 'health-probe'
    if proxy['type'] in ('trojan', 'anytls', 'tuic', 'hysteria2'):
        proxy['sni'] = proxy.get('sni') or proxy.get('servername') or original_host
    elif proxy.get('tls') or proxy.get('reality-opts'):
        proxy['servername'] = proxy.get('servername') or proxy.get('sni') or original_host
    with core_slot(directory) as acquired:
        if not acquired or deadline - time.monotonic() < 0.2:
            result.update(status='error', msg='代理检测繁忙或时间预算已用尽，请稍后重试', online=False)
            return result
        try:
            delay = run_core(proxy, directory, deadline)
        except (OSError, ValueError, RuntimeError, http.client.HTTPException):
            # Neither the core's raw error nor the configuration may enter logs/UI.
            result['stages']['auth'] = {'state': 'not_run', 'detail': '代理访问未成功，无法单独确定认证结果'}
            result['stages']['access'] = {'state': 'failed', 'detail': '实际代理 HTTPS 访问失败或超时'}
            result.update(status='failed', online=False, msg='代理访问未通过；入口结果见检测详情')
        else:
            if proxy['type'] not in ('tuic', 'hysteria2'):
                result['stages']['tcp'] = {'state': 'success', 'detail': '核心已通过此入口完成代理请求'}
            if proxy['type'] in ('trojan', 'anytls', 'tuic', 'hysteria2') or proxy.get('tls'):
                result['stages']['tls'] = {'state': 'success', 'detail': '核心按保存配置完成传输握手'}
                result['tls_mode'] = ('pinned' if proxy.get('fingerprint') else
                                      'insecure_configured' if proxy.get('skip-cert-verify') else 'strict')
            result['stages']['auth'] = {'state': 'success', 'detail': '使用此节点凭据完成实际代理请求'}
            result['stages']['access'] = {'state': 'success', 'detail': '通过此代理访问固定 HTTPS 检测地址，返回 204'}
            result.update(status='verified', online=True, msg='此节点凭据与实际代理 HTTPS 访问均验证通过',
                          proxy_latency=delay)
        result['checked_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
        return result
