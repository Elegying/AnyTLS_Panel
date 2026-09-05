"""Protocol URI and Clash conversion registry.

Each protocol owns its conversion rules here so routes and subscription fetching do
not need parallel protocol switch statements.
"""

import base64
import json
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import yaml

from input_limits import MAX_HOST_CHARS, MAX_SUBSCRIPTION_TEXT_CHARS


_MAX_YAML_NODES = 10_000
_MAX_YAML_DEPTH = 100
_MAX_YAML_ALIAS_REFERENCES = 100


class _BoundedSafeLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._node_count = 0
        self._node_depth = 0

    def compose_node(self, parent, index):
        self._node_count += 1
        self._node_depth += 1
        try:
            if self._node_count > _MAX_YAML_NODES:
                raise yaml.YAMLError('YAML node limit exceeded')
            if self._node_depth > _MAX_YAML_DEPTH:
                raise yaml.YAMLError('YAML nesting limit exceeded')
            return super().compose_node(parent, index)
        finally:
            self._node_depth -= 1


def _query_value(params, *names, default=''):
    for name in names:
        values = params.get(name)
        if values:
            return values[0]
    return default


def _is_true(value):
    return str(value).lower() in ('1', 'true', 'yes')


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _sip002_escape(value):
    escaped = str(value).replace('\\', '\\\\')
    for char in (':', ';', '='):
        escaped = escaped.replace(char, f'\\{char}')
    return escaped


def _sip002_split(value, separator, maxsplit=-1):
    parts, current = [], []
    escaped = False
    splits = 0
    for char in value:
        if escaped:
            current.extend(('\\', char))
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == separator and (maxsplit < 0 or splits < maxsplit):
            parts.append(''.join(current))
            current = []
            splits += 1
        else:
            current.append(char)
    if escaped:
        current.append('\\')
    parts.append(''.join(current))
    return parts


def _sip002_unescape(value):
    result = []
    escaped = False
    for char in value:
        if escaped:
            result.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        else:
            result.append(char)
    if escaped:
        result.append('\\')
    return ''.join(result)


def _parse_vmess_uri(uri, _protocol):
    payload = uri.split('://', 1)[1]
    payload += '=' * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload).decode())
    return {
        'name': data.get('ps', data.get('add', 'unknown')),
        'host': data.get('add', ''),
        'port': int(data.get('port', 443)),
        'password': data.get('id', ''),
        'raw_uri': uri,
        'protocol': 'vmess',
        'extra': data,
    }


def _parse_ss_uri(uri, _protocol):
    parsed = urlparse(uri)
    userinfo, separator, _hostport = parsed.netloc.rpartition('@')
    if not separator:
        return None
    try:
        padded = userinfo + '=' * (-len(userinfo) % 4)
        userinfo = base64.urlsafe_b64decode(padded).decode()
    except Exception:
        pass
    method, password = map(unquote, userinfo.split(':', 1))
    host, port = parsed.hostname, parsed.port
    if not host or not port:
        return None
    return {
        'name': unquote(parsed.fragment) if parsed.fragment else f'{host}:{port}',
        'host': host,
        'port': port,
        'password': password,
        'raw_uri': uri,
        'protocol': 'shadowsocks',
        'extra': {'cipher': method},
    }


def _parse_standard_uri(uri, protocol):
    parsed = urlparse(uri)
    encoded_password, separator, _hostport = parsed.netloc.rpartition('@')
    if not separator or not parsed.hostname or parsed.port is None:
        return None
    host, port = parsed.hostname, parsed.port
    return {
        'name': unquote(parsed.fragment) if parsed.fragment else f'{host}:{port}',
        'host': host,
        'port': port,
        'password': unquote(encoded_password),
        'raw_uri': uri,
        'protocol': protocol,
        'extra': parse_qs(parsed.query),
    }


def parse_protocol_uri(uri, protocol='anytls'):
    """Parse a supported URI into the stable node dictionary model."""
    try:
        uri = uri.strip()
        codec = CODECS.get(protocol, {})
        parser = codec.get('parse_uri', _parse_standard_uri)
        node = parser(uri, protocol)
        if not node or not all(
            isinstance(node.get(field), str) for field in ('name', 'host', 'password')
        ):
            return None
        if not 1 <= len(node['host']) <= MAX_HOST_CHARS or not 1 <= node['port'] <= 65535:
            return None
        return node
    except Exception:
        return None


def _clash_context(proxy):
    ptype = str(proxy.get('type', '')).lower().replace('-', '').replace('_', '')
    host = proxy.get('server', '')
    port = int(proxy.get('port', 443))
    if not host or not 1 <= port <= 65535:
        raise ValueError('invalid Clash proxy endpoint')
    ws_opts = proxy.get('ws-opts') if isinstance(proxy.get('ws-opts'), dict) else {}
    return {
        'proxy': proxy,
        'ptype': ptype,
        'host': host,
        'port': port,
        'password': proxy.get('password', '') or proxy.get('uuid', ''),
        'name': proxy.get('name', f'{host}:{port}'),
        'network': proxy.get('network', 'tcp') or 'tcp',
        'ws_opts': ws_opts,
        'ws_headers': ws_opts.get('headers') if isinstance(ws_opts.get('headers'), dict) else {},
        'grpc_opts': proxy.get('grpc-opts') if isinstance(proxy.get('grpc-opts'), dict) else {},
        'reality_opts': proxy.get('reality-opts') if isinstance(proxy.get('reality-opts'), dict) else {},
        'servername': proxy.get('servername') or proxy.get('sni') or host,
        'insecure': '1' if proxy.get('skip-cert-verify') else '0',
        'fingerprint': proxy.get('client-fingerprint') or proxy.get('fingerprint') or '',
    }


def _build_uri(context, scheme, credential, query):
    host = context['host']
    authority_host = f'[{host}]' if ':' in str(host) else host
    query_string = urlencode({
        key: value for key, value in query.items()
        if value is not None and value != ''
    })
    suffix = f'?{query_string}' if query_string else ''
    fragment = quote(str(context['name']), safe='')
    return (
        f"{scheme}://{quote(str(credential), safe='')}@"
        f"{authority_host}:{context['port']}{suffix}#{fragment}"
    )


def _from_anytls(context):
    p = context['proxy']
    return _build_uri(context, 'anytls', context['password'], {
        'security': 'tls', 'sni': context['servername'],
        'allowInsecure': context['insecure'], 'fp': context['fingerprint'],
        'idleSessionCheckInterval': p.get('idle-session-check-interval'),
        'idleSessionTimeout': p.get('idle-session-timeout'),
        'minIdleSession': p.get('min-idle-session'),
    })


def _from_trojan(context):
    return _build_uri(context, 'trojan', context['password'], {
        'sni': context['servername'], 'allowInsecure': context['insecure'],
        'fp': context['fingerprint'], 'type': context['network'],
        'path': context['ws_opts'].get('path', ''),
        'host': context['ws_headers'].get('Host', ''),
        'serviceName': context['grpc_opts'].get('grpc-service-name', ''),
    })


def _from_vmess(context):
    p = context['proxy']
    obj = {
        'v': '2', 'ps': context['name'], 'add': context['host'],
        'port': str(context['port']), 'id': context['password'],
        'aid': str(p.get('alterId', 0)), 'scy': p.get('cipher', 'auto'),
        'net': context['network'], 'type': 'none',
        'host': context['ws_headers'].get('Host', ''),
        'path': context['ws_opts'].get('path', ''),
        'serviceName': context['grpc_opts'].get('grpc-service-name', ''),
        'tls': 'tls' if p.get('tls') else 'none',
        'sni': context['servername'] if p.get('tls') else '',
        'fp': context['fingerprint'], 'allowInsecure': context['insecure'],
    }
    encoded = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
    return f'vmess://{encoded}'


def _from_vless(context):
    p, reality = context['proxy'], context['reality_opts']
    return _build_uri(context, 'vless', context['password'], {
        'security': 'reality' if reality else ('tls' if p.get('tls') else 'none'),
        'sni': context['servername'], 'flow': p.get('flow', ''),
        'type': context['network'], 'path': context['ws_opts'].get('path', ''),
        'host': context['ws_headers'].get('Host', ''),
        'serviceName': context['grpc_opts'].get('grpc-service-name', ''),
        'allowInsecure': context['insecure'], 'fp': context['fingerprint'],
        'encryption': p.get('encryption', ''),
        'packetEncoding': p.get('packet-encoding', ''),
        'pbk': reality.get('public-key', ''), 'sid': reality.get('short-id', ''),
    })


def _from_hysteria2(context):
    p = context['proxy']
    return _build_uri(context, 'hysteria2', context['password'], {
        'sni': context['servername'], 'allowInsecure': context['insecure'],
        'obfs': p.get('obfs', ''), 'obfs-password': p.get('obfs-password', ''),
    })


def _from_tuic(context):
    credential = f"{context['proxy'].get('uuid', '')}:{context['password']}"
    return _build_uri(context, 'tuic', credential, {
        'sni': context['servername'], 'allowInsecure': context['insecure'],
    })


def _from_shadowsocks(context):
    p = context['proxy']
    method, password = p.get('cipher', 'aes-256-gcm'), context['password']
    if str(method).startswith('2022-blake3-'):
        userinfo = f"{quote(str(method), safe='')}:{quote(str(password), safe='')}"
    else:
        userinfo = base64.urlsafe_b64encode(
            f'{method}:{password}'.encode()
        ).decode().rstrip('=')
    host = context['host']
    authority_host = f'[{host}]' if ':' in str(host) else host
    query = {}
    if p.get('plugin'):
        parts = [_sip002_escape(p['plugin'])]
        if isinstance(p.get('plugin-opts'), dict):
            for key, value in p['plugin-opts'].items():
                if value is True:
                    parts.append(_sip002_escape(key))
                elif value not in (None, False):
                    parts.append(f'{_sip002_escape(key)}={_sip002_escape(value)}')
        query['plugin'] = ';'.join(parts)
    suffix = f'/?{urlencode(query)}' if query else ''
    fragment = quote(str(context['name']), safe='')
    return f"ss://{userinfo}@{authority_host}:{context['port']}{suffix}#{fragment}"


def _from_unknown(context):
    return _build_uri(context, context['ptype'], context['password'], {})


def parse_clash_yaml(content):
    """Convert all valid Clash proxies using the registered protocol codec."""
    if not isinstance(content, str) or len(content) > MAX_SUBSCRIPTION_TEXT_CHARS:
        return []
    try:
        alias_count = sum(
            isinstance(token, yaml.tokens.AliasToken)
            for token in yaml.scan(content)
        )
        if alias_count > _MAX_YAML_ALIAS_REFERENCES:
            return []
        loader = _BoundedSafeLoader(content)
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get('proxies') or data.get('Proxy') or []
    if not isinstance(proxies, list):
        return []
    nodes = []
    for proxy in proxies:
        try:
            if not isinstance(proxy, dict):
                continue
            context = _clash_context(proxy)
            codec = CODECS.get(context['ptype'], {})
            uri = codec.get('from_clash', _from_unknown)(context)
            canonical = codec.get('canonical', context['ptype'])
            nodes.append({
                'name': str(context['name']), 'host': str(context['host']),
                'port': context['port'], 'password': str(context['password']),
                'raw_uri': uri, 'protocol': canonical,
                'extra': {key: value for key, value in proxy.items()
                          if key not in ('name', 'type', 'server', 'port', 'password')},
            })
        except (TypeError, ValueError):
            continue
    return nodes


def _allow_insecure(params):
    return _is_true(_query_value(
        params, 'allowInsecure', 'allow-insecure', 'insecure', default='0'
    ))


def _apply_stream(proxy, params):
    network = _query_value(params, 'type', 'network')
    if network:
        proxy['network'] = network
    if network == 'ws':
        options = {'path': _query_value(params, 'path', default='/') or '/'}
        host = _query_value(params, 'host')
        if host:
            options['headers'] = {'Host': host}
        proxy['ws-opts'] = options
    elif network == 'grpc':
        service_name = _query_value(params, 'serviceName')
        if service_name:
            proxy['grpc-opts'] = {'grpc-service-name': service_name}


def _to_anytls(proxy, node, params):
    proxy.update({
        'type': 'anytls', 'password': node['password'], 'udp': True,
        'sni': _query_value(params, 'sni', default=node['host']) or node['host'],
        'skip-cert-verify': _allow_insecure(params),
    })
    fingerprint = _query_value(params, 'fp')
    if fingerprint:
        proxy['client-fingerprint'] = fingerprint
    for query_key, clash_key in (
        ('idleSessionCheckInterval', 'idle-session-check-interval'),
        ('idleSessionTimeout', 'idle-session-timeout'),
        ('minIdleSession', 'min-idle-session'),
    ):
        value = _query_value(params, query_key)
        if value:
            proxy[clash_key] = _safe_int(value, value)


def _to_vmess(proxy, node, _params):
    extra = node.get('extra', {})
    proxy.update({
        'type': 'vmess', 'uuid': node['password'],
        'alterId': _safe_int(extra.get('aid', 0) or 0),
        'cipher': extra.get('scy', 'auto') or 'auto',
    })
    network = extra.get('net', 'tcp') or 'tcp'
    if network != 'tcp':
        proxy['network'] = network
    if str(extra.get('tls', '')).lower() in ('tls', '1', 'true'):
        proxy['tls'] = True
    for source, target in (('sni', 'servername'), ('fp', 'client-fingerprint')):
        if extra.get(source):
            proxy[target] = extra[source]
    if _is_true(extra.get('allowInsecure', '0')):
        proxy['skip-cert-verify'] = True
    if network == 'ws':
        options = {'path': extra.get('path', '') or '/'}
        if extra.get('host'):
            options['headers'] = {'Host': extra['host']}
        proxy['ws-opts'] = options
    elif network == 'grpc' and extra.get('serviceName'):
        proxy['grpc-opts'] = {'grpc-service-name': extra['serviceName']}


def _to_shadowsocks(proxy, node, params):
    proxy.update({
        'type': 'ss',
        'cipher': node.get('extra', {}).get('cipher', 'aes-256-gcm'),
        'password': node['password'],
    })
    plugin = _query_value(params, 'plugin')
    if plugin:
        parts = _sip002_split(plugin, ';')
        proxy['plugin'] = _sip002_unescape(parts[0])
        options = {}
        for option in parts[1:]:
            pair = _sip002_split(option, '=', maxsplit=1)
            if len(pair) == 2:
                key, value = map(_sip002_unescape, pair)
                options[key] = value
            elif option:
                options[_sip002_unescape(option)] = True
        if options:
            proxy['plugin-opts'] = options
    encoded = _query_value(params, 'pluginOpts')
    if encoded and 'plugin-opts' not in proxy:
        try:
            encoded += '=' * (-len(encoded) % 4)
            proxy['plugin-opts'] = json.loads(base64.urlsafe_b64decode(encoded).decode())
        except (ValueError, TypeError, UnicodeDecodeError):
            pass


def _tls_name(node, params):
    return _query_value(params, 'sni', 'peer', default=node['host']) or node['host']


def _to_trojan(proxy, node, params):
    proxy.update({
        'type': 'trojan', 'password': node['password'],
        'sni': _tls_name(node, params),
        'skip-cert-verify': _allow_insecure(params),
    })
    fingerprint = _query_value(params, 'fp')
    if fingerprint:
        proxy['client-fingerprint'] = fingerprint
    _apply_stream(proxy, params)


def _to_vless(proxy, node, params):
    security = _query_value(params, 'security')
    proxy.update({
        'type': 'vless', 'uuid': node['password'],
        'servername': _tls_name(node, params),
        'skip-cert-verify': _allow_insecure(params),
    })
    if security in ('tls', 'reality'):
        proxy['tls'] = True
    if security == 'reality':
        reality = {}
        public_key, short_id = _query_value(params, 'pbk'), _query_value(params, 'sid')
        if public_key:
            reality['public-key'] = public_key
        if short_id:
            reality['short-id'] = short_id
        if reality:
            proxy['reality-opts'] = reality
    for query_key, clash_key in (
        ('flow', 'flow'), ('fp', 'client-fingerprint'),
        ('encryption', 'encryption'), ('packetEncoding', 'packet-encoding'),
    ):
        value = _query_value(params, query_key)
        if value:
            proxy[clash_key] = value
    _apply_stream(proxy, params)


def _to_hysteria2(proxy, node, params):
    proxy.update({
        'type': 'hysteria2', 'password': node['password'],
        'sni': _tls_name(node, params),
        'skip-cert-verify': _allow_insecure(params),
    })
    for key in ('obfs', 'obfs-password'):
        value = _query_value(params, key)
        if value:
            proxy[key] = value


def _to_tuic(proxy, node, params):
    proxy.update({
        'type': 'tuic', 'sni': _tls_name(node, params),
        'skip-cert-verify': _allow_insecure(params),
    })
    if ':' in node['password']:
        proxy['uuid'], proxy['password'] = node['password'].split(':', 1)
    else:
        proxy['password'] = node['password']


def _to_unknown(proxy, node, _params):
    proxy.update({'type': node['protocol'], 'password': node['password']})


def clash_proxy_from_uri(uri):
    """Convert a URI into a Clash proxy through the registered codec."""
    scheme = uri.split('://', 1)[0].lower()
    protocol = 'ss' if scheme == 'ss' else scheme
    node = parse_protocol_uri(uri, protocol)
    if not node:
        return None
    proxy = {'name': node['name'], 'server': node['host'], 'port': node['port']}
    params = parse_qs(urlparse(uri).query)
    codec = CODECS.get(node['protocol'], {})
    codec.get('to_clash', _to_unknown)(proxy, node, params)
    return proxy


CODECS = {
    'anytls': {'parse_uri': _parse_standard_uri, 'from_clash': _from_anytls,
               'to_clash': _to_anytls},
    'anytls1': {'parse_uri': _parse_standard_uri, 'from_clash': _from_anytls,
                'to_clash': _to_anytls},
    'trojan': {'parse_uri': _parse_standard_uri, 'from_clash': _from_trojan,
               'to_clash': _to_trojan},
    'vmess': {'parse_uri': _parse_vmess_uri, 'from_clash': _from_vmess,
              'to_clash': _to_vmess},
    'vless': {'parse_uri': _parse_standard_uri, 'from_clash': _from_vless,
              'to_clash': _to_vless},
    'hysteria2': {'parse_uri': _parse_standard_uri, 'from_clash': _from_hysteria2,
                  'to_clash': _to_hysteria2},
    'hy2': {'parse_uri': _parse_standard_uri, 'from_clash': _from_hysteria2,
            'to_clash': _to_hysteria2},
    'hysteria': {'parse_uri': _parse_standard_uri, 'from_clash': _from_hysteria2,
                 'to_clash': _to_hysteria2},
    'tuic': {'parse_uri': _parse_standard_uri, 'from_clash': _from_tuic,
             'to_clash': _to_tuic},
    'ss': {'parse_uri': _parse_ss_uri, 'from_clash': _from_shadowsocks,
           'to_clash': _to_shadowsocks, 'canonical': 'shadowsocks'},
    'shadowsocks': {'parse_uri': _parse_ss_uri, 'from_clash': _from_shadowsocks,
                    'to_clash': _to_shadowsocks, 'canonical': 'shadowsocks'},
}
