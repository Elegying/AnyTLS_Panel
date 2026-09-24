"""Shared subscription policy, naming and bounded output generation."""
import base64
import json
from urllib.parse import quote

from input_limits import MAX_EXPORT_BYTES, MAX_NODE_NAME_CHARS, MAX_RENAME_RULES
from protocol_codecs import clash_proxy_from_uri as _clash_proxy_from_uri, uri_preserves_clash_config

# Mihomo built-in outbound/group names cannot also identify a user proxy.
RESERVED_NAMES = frozenset(('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'))

def apply_rename(text, rules):
    """Reject expansion before allocating the replacement string."""
    if len(text) > MAX_NODE_NAME_CHARS or len(rules) > MAX_RENAME_RULES:
        raise ValueError('节点名称或重命名规则数量超过上限')
    for r in rules:
        old, new = r['old_text'], r['new_text']
        if not old:
            raise ValueError('重命名匹配文字不能为空')
        projected = len(text) + text.count(old) * (len(new) - len(old))
        if projected > MAX_NODE_NAME_CHARS:
            raise ValueError(f'重命名后的节点名称不能超过 {MAX_NODE_NAME_CHARS} 个字符')
        text = text.replace(old, new)
    return text


def validate_rename_rules(rules, names):
    if len(rules) > MAX_RENAME_RULES:
        raise ValueError(f'重命名规则最多 {MAX_RENAME_RULES} 条')
    for name in names:
        apply_rename(name, rules)


def rename_node_uri(node, rules, *, name=None):
    raw_uri = node.get('raw_uri', '')
    original_name = str(node.get('name', ''))
    renamed = apply_rename(original_name, rules) if name is None else name
    if not raw_uri or renamed == original_name:
        return raw_uri
    if raw_uri.startswith('vmess://'):
        try:
            encoded = raw_uri.split('://', 1)[1]
            payload = encoded + '=' * (-len(encoded) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload).decode())
            data['ps'] = renamed
            encoded = base64.urlsafe_b64encode(
                json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            return f'vmess://{encoded}'
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return raw_uri
    base, _separator, _fragment = raw_uri.partition('#')
    return f"{base}#{quote(renamed, safe='')}"


def prepare_subscription(nodes, keywords, rules):
    """Apply policy once, keeping final names and routing references consistent."""
    selected = [n for n in nodes if not any(k.casefold() in n['name'].casefold() for k in keywords)]
    blocked = len(nodes) - len(selected)
    original_names = {}
    for index, node in enumerate(selected):
        original_names.setdefault(node['name'], []).append(index)
        node['proxy'] = (json.loads(node['clash_config']) if node['clash_config']
                         else _clash_proxy_from_uri(node['raw_uri']))
    # A removed/ambiguous dependency or a cycle must never become a direct connection.
    valid = set()
    for index in range(len(selected)):
        chain, current = set(), index
        while current not in valid and current not in chain:
            chain.add(current)
            proxy = selected[current]['proxy'] or {}
            dependency = proxy.get('dialer-proxy')
            if not dependency or dependency == 'DIRECT':
                valid.update(chain)
                break
            targets = original_names.get(dependency, [])
            if len(targets) != 1:
                break
            current = targets[0]
        else:
            if current in valid:
                valid.update(chain)
    selected = [n for i, n in enumerate(selected) if i in valid]
    desired = [apply_rename(n['name'], rules).strip() or '节点' for n in selected]
    # Reserve all desired names so generated suffixes do not steal another node's name.
    reserved, used = set(desired) | RESERVED_NAMES, set(RESERVED_NAMES)
    mapping = {}
    for node, name in zip(selected, desired):
        candidate, suffix = name, 2
        if candidate in used:
            candidate = f'{name[:MAX_NODE_NAME_CHARS - len(str(suffix)) - 3]} [{suffix}]'
            while candidate in used or candidate in reserved:
                suffix += 1
                candidate = f'{name[:MAX_NODE_NAME_CHARS - len(str(suffix)) - 3]} [{suffix}]'
        used.add(candidate)
        mapping[node['name']] = candidate
        node['export_name'] = candidate
    links, proxies, requires_clash = [], [], False
    output_bytes = 0
    for node in selected:
        # Use the existing URI encoder with one exact final-name replacement.
        uri = rename_node_uri(node, [], name=node['export_name'])
        links.append(uri)
        proxy = node['proxy']
        if proxy:
            if node['clash_config'] and not uri_preserves_clash_config(proxy, node['raw_uri']):
                requires_clash = True
            proxy['name'] = node['export_name']
            if proxy.get('dialer-proxy') not in (None, '', 'DIRECT'):
                proxy['dialer-proxy'] = mapping[proxy['dialer-proxy']]
            proxies.append(proxy)
        output_bytes += len(uri.encode()) + len(json.dumps(proxy, ensure_ascii=False).encode())
        # Reserve room for Base64/YAML formatting and separators.
        if output_bytes > MAX_EXPORT_BYTES // 2:
            raise ValueError('订阅输出超过大小上限，请减少节点或规则')
    return {'links': links, 'proxies': proxies, 'requires_clash': requires_clash,
            'stored': len(nodes), 'blocked': blocked,
            'unavailable': len(nodes) - blocked - len(selected),
            'count': len(selected), 'names': [n['export_name'] for n in selected]}
