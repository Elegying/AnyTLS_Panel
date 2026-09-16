"""Bounded, address-pinned entry probes; never claim proxy authentication."""

import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from protocol_codecs import parse_protocol_uri

PROBE_TTL_SECONDS = 900
STAGE_LABELS = {'dns': 'DNS 解析', 'tcp': 'TCP 建连', 'tls': 'TLS 握手',
                'auth': '代理认证', 'access': '代理访问'}
OUTCOME_LABELS = {'success': '成功', 'failed': '失败', 'not_run': '未执行',
                  'not_applicable': '不适用', 'unsupported': '不支持'}
STATUS_LABELS = {'unknown': '未检测', 'checking': '检测中',
                 'entry': '入口可达，代理未验证', 'tls_error': 'TLS 异常',
                 'verified': '代理验证通过', 'failed': '检测失败',
                 'expired': '结果已过期，需要复测', 'error': '检测未完成',
                 'unsupported': '仅完成部分检测，代理未验证'}


def _validated_addresses(addresses, allow_private):
    validated = []
    for raw_address in addresses:
        try:
            address = str(raw_address).split('%', 1)[0]
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError('节点地址解析结果无效') from exc
        if not allow_private and not ip.is_global:
            raise ValueError('节点检测默认只允许公网地址')
        if address not in validated:
            validated.append(address)
    if not validated:
        raise ValueError('节点地址无法解析')
    return validated


def probe_options(node):
    """Only plain TCP/TLS is implemented. Never emulate QUIC/REALITY/plugins."""
    node = dict(node or {})
    protocol = (node.get('protocol') or '').lower()
    uri = node.get('raw_uri') or ''
    parsed = parse_protocol_uri(uri, protocol) if uri else None
    if uri and not parsed:
        return {'tcp': False, 'tls': 'unsupported', 'note': '配置无法解析，未执行网络探测'}
    params = (parsed or {}).get('extra', {})

    def value(*keys, default=''):
        for key in keys:
            v = params.get(key)
            if v is not None:
                return str(v[0] if isinstance(v, list) else v)
        return default

    if protocol in ('hysteria2', 'hysteria', 'tuic', 'hy2'):
        return {'tcp': False, 'tls': 'unsupported', 'note': 'UDP / QUIC 探测暂不支持'}
    if protocol not in ('anytls', 'trojan', 'vmess', 'vless', 'shadowsocks', 'ss'):
        return {'tcp': True, 'tls': 'unsupported', 'note': '仅检测 TCP；此协议暂不支持'}
    security = value('security', 'tls', default='tls' if protocol in ('anytls', 'trojan') else 'none')
    transport = value('type', 'network', default='tcp') if protocol != 'vmess' else value('net', default='tcp')
    plugin = parse_qs(urlparse(uri).query).get('plugin') if uri else None
    if (security == 'reality' or transport not in ('tcp', 'raw', 'ws', 'grpc', 'h2', 'http')
            or plugin or value('fp', 'fingerprint', 'client-fingerprint')):
        return {'tcp': True, 'tls': 'unsupported', 'note': '仅检测 TCP；特殊传输 / REALITY / 插件 / 客户端指纹未验证'}
    if security not in ('tls', 'none', ''):
        return {'tcp': True, 'tls': 'unsupported', 'note': '仅检测 TCP；TLS 配置暂不支持'}
    sni = value('sni', 'peer', 'servername', 'serverName', default=node.get('host', ''))
    # A configured empty SNI falls back to the endpoint, matching URI codecs.
    sni = sni or node.get('host', '')
    insecure = value('allowInsecure', 'allow-insecure', 'insecure', 'skip-cert-verify', default='0').lower() in ('1', 'true', 'yes')
    alpn = value('alpn')
    if not alpn and transport in ('grpc', 'h2'):
        alpn = 'h2'
    return {'tcp': True, 'tls': 'run' if security == 'tls' else 'not_applicable',
            'sni': sni, 'insecure': insecure, 'alpn': alpn.split(',') if alpn else [],
            'note': '仅验证入口；传输升级、代理认证和代理访问均未验证'}


def entry_probe_key(node):
    """Group entry checks only; never use this key for account authentication."""
    node = dict(node)
    protocol = (node.get('protocol') or 'anytls').lower()
    uri = node.get('raw_uri') or ''
    parsed = parse_protocol_uri(uri, protocol) if uri else None
    if uri and not parsed:
        return None  # Unparseable configurations must remain independent.
    extra = dict((parsed or {}).get('extra', {}))
    if protocol == 'vmess':
        extra.pop('id', None)  # Account UUID; entry checks do not authenticate.
        extra.pop('ps', None)  # Display name.
    elif uri:
        extra.update(parse_qs(urlparse(uri).query))  # Includes SS plugin options.
    return (protocol, node['host'].lower(), node['port'],
            json.dumps([probe_options(node), extra], sort_keys=True, ensure_ascii=False))


def check_node_connect(host, port, timeout, resolver, *, allow_private=False, node=None):
    """Every socket uses the validated literal address and one absolute deadline."""
    options = probe_options(node)
    stages = {key: {'state': 'not_run', 'detail': '未验证'} for key in STAGE_LABELS}
    result = {'version': 1, 'online': False, 'status': 'failed', 'latency': -1,
              'source': 'panel_server', 'stages': stages,
              'tls_mode': 'not_run', 'msg': ''}

    def finish(status, message):
        result.update(status=status, msg=message, online=status == 'entry',
                      checked_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
        return result

    deadline = time.monotonic() + timeout
    try:
        raw_addresses = resolver(host, port, deadline)
    except (ValueError, OSError, TimeoutError):
        stages['dns'] = {'state': 'failed', 'detail': '节点地址解析失败或超时'}
        return finish('failed', '节点地址解析失败或超时')
    try:
        addresses = _validated_addresses(raw_addresses, allow_private)
    except ValueError:
        stages['dns'] = {'state': 'failed', 'detail': '地址安全检查失败：默认只允许公网地址'}
        return finish('failed', stages['dns']['detail'])
    stages['dns'] = {'state': 'success', 'detail': '已解析并固定通过安全检查的地址'}
    if not options['tcp']:
        stages['tcp'] = {'state': 'not_applicable', 'detail': options['note']}
        stages['tls'] = {'state': 'unsupported', 'detail': options['note']}
        return finish('unsupported', options['note'])

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError
        return value

    last_error = 'TCP 连接失败'
    started = time.monotonic()
    attempted = False
    for address in addresses:
        sock = None
        try:
            connect_timeout = remaining()
        except TimeoutError:
            if not attempted:
                return finish('error', '检测时间预算已用尽，未执行 TCP')
            break
        try:
            attempted = True
            sock = socket.create_connection((address, port), timeout=connect_timeout)
            result['latency'] = int((time.monotonic() - started) * 1000)
            stages['tcp'] = {'state': 'success', 'detail': '入口 TCP 可达；不是代理延迟'}
            if options['tls'] != 'run':
                stages['tls'] = {'state': options['tls'], 'detail': options['note']}
                return finish('entry', options['note'])
            result['tls_mode'] = 'insecure_configured' if options['insecure'] else 'strict'
            try:
                tls_timeout = remaining()
            except TimeoutError:
                stages['tls'] = {'state': 'not_run', 'detail': '总时间预算已用尽，未执行 TLS'}
                return finish('error', '检测时间预算已用尽，不能判断 TLS 或代理状态')
            try:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                if options['insecure']:
                    # Explicit node setting only; never a fallback after TLS failure.
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                if options['alpn']:
                    context.set_alpn_protocols(options['alpn'])
                sock.settimeout(tls_timeout)
                sock = context.wrap_socket(sock, server_hostname=options['sni'])
                detail = ('握手成功；节点配置跳过证书验证，证书有效性未验证'
                          if options['insecure'] else '握手和证书域名校验成功')
                stages['tls'] = {'state': 'success', 'detail': detail}
                return finish('entry', options['note'])
            except (ssl.SSLError, OSError, TimeoutError, ValueError):
                stages['tls'] = {'state': 'failed', 'detail': 'TLS 握手、证书校验失败或超时'}
                return finish('tls_error', 'TCP 已成功；TLS 异常，代理未验证')
        except (socket.timeout, TimeoutError):
            last_error = 'TCP 连接超时'
        except ConnectionRefusedError:
            last_error = 'TCP 连接被拒绝'
        except OSError:
            last_error = 'TCP 连接失败'
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    stages['tcp'] = {'state': 'failed', 'detail': last_error}
    return finish('failed', last_error)


def node_health(node, now=None):
    """One presentation contract for API, all pages, and legacy database rows."""
    node = dict(node)
    now = now or datetime.now(timezone.utc)
    try:
        result = json.loads(node.get('probe_result') or '{}')
        if not isinstance(result, dict):
            result = {}
    except (ValueError, TypeError):
        result = {}
    legacy = not result
    checked = result.get('checked_at') or node.get('last_checked_at')
    timestamp = None
    try:
        timestamp = datetime.fromisoformat(checked.replace(' UTC', '+00:00').replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
    except (AttributeError, ValueError):
        pass
    age = max(0, int((now - timestamp).total_seconds())) if timestamp else None
    stages = result.get('stages') or {key: {'state': 'not_run', 'detail': '旧版未记录分层结果'} for key in STAGE_LABELS}
    status = result.get('status', 'unknown')
    if status not in STATUS_LABELS:
        status = 'unknown'
    # No legacy online flag or a bare status string can establish proxy usability.
    if status == 'verified' and not all(stages.get(k, {}).get('state') == 'success' for k in ('auth', 'access')):
        status = 'entry' if stages.get('tcp', {}).get('state') == 'success' else 'unknown'
    previous = STATUS_LABELS[status]
    if legacy and checked:
        previous = '历史入口检测可达（代理未验证）' if node.get('is_online') == 1 else '历史检测结果（需复测）'
    if timestamp and (legacy or age >= PROBE_TTL_SECONDS or timestamp.timestamp() > now.timestamp() + 60):
        status = 'expired'
    elif not timestamp:
        status = 'unknown'
    if node.get('probe_error'):
        status = 'error'
    if node.get('probe_running'):
        status = 'checking'
    tone = 'green' if status == 'verified' else 'red' if status in ('failed', 'tls_error') else 'orange' if status in ('entry', 'expired', 'error', 'unsupported') else 'neutral'
    label = '旧版结果待复测' if legacy and checked and status == 'expired' else STATUS_LABELS[status]
    return {'status': status, 'label': label, 'tone': tone,
            'previous': previous, 'msg': node.get('probe_error') or result.get(
                'msg', '旧版未记录检测阶段，请点击检测取得新结果' if legacy and checked else '尚未取得分层检测结果'),
            'stages': [{'key': key, 'label': label, 'state': stages.get(key, {}).get('state', 'not_run'),
                        'outcome': OUTCOME_LABELS.get(stages.get(key, {}).get('state'), '未执行'),
                        'detail': stages.get(key, {}).get('detail', '未验证')} for key, label in STAGE_LABELS.items()],
            'checked_at': timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp else None,
            'age_seconds': age, 'ttl_seconds': PROBE_TTL_SECONDS,
            'expires_at': timestamp.timestamp() + PROBE_TTL_SECONDS if timestamp else None,
            'latency': result.get('latency', -1),
            'tls_mode': result.get('tls_mode', 'not_recorded'), 'source': '面板服务器',
            'attempt_at': node.get('probe_attempt_at')}
