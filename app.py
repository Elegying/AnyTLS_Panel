#!/usr/bin/env python3
"""AnyTLS 多节点统一管理面板 — 订阅导入模式"""

import os
import json
import re
import sqlite3
import secrets
import base64
import time
import sys
import hmac
import math
import ipaddress
import socket
import ssl
import http.client
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qs, unquote
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, g
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from security_utils import hash_password, verify_password
from traffic_token import make_account_traffic_token


def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def _database_path():
    configured = os.environ.get('ANYTLS_DATABASE')
    if configured is not None:
        configured = configured.strip()
        if not configured:
            raise RuntimeError('ANYTLS_DATABASE must be a non-empty file path')
    path = Path(configured or os.path.join(os.path.dirname(__file__), 'anytls.db'))
    if path.exists() and not path.is_file():
        raise RuntimeError('ANYTLS_DATABASE must point to a regular file')
    return str(path)


app = Flask(__name__)
app.config['DATABASE'] = _database_path()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = _env_flag('ANYTLS_SESSION_COOKIE_SECURE')
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24小时
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token 1小时有效

if _env_flag('ANYTLS_TRUST_PROXY'):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# CSRF 保护
csrf = CSRFProtect(app)

# 登录速率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=os.environ.get('ANYTLS_RATE_LIMIT_STORAGE_URI', 'memory://'),
)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


def _read_or_create_private_file(path, value_factory, trailing_newline=False):
    path = Path(path)
    try:
        existing = path.read_text(encoding='utf-8').strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass

    value = value_factory()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        for _ in range(100):
            existing = path.read_text(encoding='utf-8').strip()
            if existing:
                return existing
            time.sleep(0.01)
        raise OSError(f'private file remained empty: {path}')

    with os.fdopen(fd, 'w', encoding='utf-8') as file_handle:
        file_handle.write(value)
        if trailing_newline:
            file_handle.write('\n')
        file_handle.flush()
        os.fsync(file_handle.fileno())
    return value


# 固定 secret_key，存文件持久化，多 worker 共享
_sk_file = os.environ.get('ANYTLS_SECRET_KEY_FILE') or os.path.join(os.path.dirname(__file__), '.secret_key')
app.secret_key = _read_or_create_private_file(_sk_file, lambda: secrets.token_hex(32))

# ─── 数据库 ──────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=15000")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def get_initial_admin_credentials():
    admin_user = os.environ.get('ANYTLS_ADMIN_USER', 'admin').strip() or 'admin'
    env_password = os.environ.get('ANYTLS_ADMIN_PASS')
    if env_password:
        return admin_user, env_password, ''

    password_file = Path(
        os.environ.get('ANYTLS_ADMIN_PASSWORD_FILE')
        or Path(app.config['DATABASE']).with_name('.initial_admin_password')
    )
    try:
        if password_file.exists():
            password = password_file.read_text(encoding='utf-8').strip()
            if password:
                app.config['INITIAL_ADMIN_PASSWORD_FILE'] = str(password_file)
                return admin_user, password, str(password_file)

        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        password = _read_or_create_private_file(
            password_file,
            lambda: ''.join(secrets.choice(alphabet) for _ in range(18)),
            trailing_newline=True,
        )
        app.config['INITIAL_ADMIN_PASSWORD_FILE'] = str(password_file)
        return admin_user, password, str(password_file)
    except OSError:
        password = secrets.token_urlsafe(18)
        return admin_user, password, ''


def get_traffic_api_token():
    env_token = os.environ.get('ANYTLS_TRAFFIC_API_TOKEN', '').strip()
    if env_token:
        return env_token

    token_file = Path(
        os.environ.get('ANYTLS_TRAFFIC_API_TOKEN_FILE')
        or Path(app.config['DATABASE']).with_name('.traffic_api_token')
    )
    app.config['TRAFFIC_API_TOKEN_FILE'] = str(token_file)

    try:
        if token_file.exists():
            token = token_file.read_text(encoding='utf-8').strip()
            if token:
                return token

        token = secrets.token_urlsafe(32)
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(token + '\n', encoding='utf-8')
        try:
            token_file.chmod(0o600)
        except OSError:
            pass
        return token
    except OSError:
        return ''


def _request_api_token():
    auth = request.headers.get('Authorization', '').strip()
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return request.headers.get('X-API-Token', '').strip()


def generate_account_traffic_token(account_id):
    account_id = parse_nonnegative_int(account_id, 'account_id')
    master_token = get_traffic_api_token()
    if not master_token:
        raise RuntimeError('traffic api token is not configured')
    return make_account_traffic_token(master_token, account_id)


def _validate_traffic_api_token(supplied, master_token):
    if hmac.compare_digest(supplied, master_token):
        return True, None
    try:
        prefix, raw_account_id, signature = supplied.split('.', 2)
        if prefix != 'atp1' or not raw_account_id.isdigit():
            return False, None
        account_id = int(raw_account_id)
        expected = generate_account_traffic_token(account_id)
    except (TypeError, ValueError, RuntimeError):
        return False, None
    return hmac.compare_digest(supplied, expected), account_id


def _payload_matches_traffic_scope(account_id):
    payload = request.get_json(silent=True)
    items = payload if isinstance(payload, list) else [payload]
    if not items:
        return False
    for item in items:
        if not isinstance(item, dict):
            return False
        try:
            if parse_nonnegative_int(item.get('account_id'), 'account_id') != account_id:
                return False
        except ValueError:
            return False
    return True


def require_traffic_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        expected = get_traffic_api_token()
        supplied = _request_api_token()
        if not expected:
            return jsonify({"error": "traffic api token is not configured"}), 503
        valid, account_scope = _validate_traffic_api_token(supplied, expected)
        if not supplied or not valid:
            return jsonify({"error": "invalid traffic api token"}), 401
        if account_scope is not None and not _payload_matches_traffic_scope(account_scope):
            return jsonify({
                "error": "account-scoped token requires its matching account_id"
            }), 403
        g.traffic_account_scope = account_scope
        return f(*args, **kwargs)
    return decorated


def init_db():
    db = sqlite3.connect(app.config['DATABASE'], timeout=30)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=30000')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subscribe_url TEXT NOT NULL,
            traffic_limit_gb REAL DEFAULT 250,
            traffic_used_bytes INTEGER DEFAULT 0,
            traffic_upload_bytes INTEGER DEFAULT 0,
            traffic_download_bytes INTEGER DEFAULT 0,
            expire_date TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            notes TEXT DEFAULT '',
            node_count INTEGER DEFAULT 0,
            last_synced_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            password TEXT NOT NULL,
            protocol TEXT DEFAULT 'anytls',
            raw_uri TEXT DEFAULT '',
            is_online INTEGER DEFAULT -1,
            latency_ms INTEGER DEFAULT -1,
            last_checked_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            bytes_used INTEGER NOT NULL,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS traffic_collectors (
            collector_id TEXT PRIMARY KEY,
            account_id INTEGER NOT NULL,
            last_counter_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rename_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_text TEXT NOT NULL,
            new_text TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_nodes_host_port ON nodes(host, port);
        CREATE INDEX IF NOT EXISTS idx_nodes_account_id ON nodes(account_id);
        CREATE INDEX IF NOT EXISTS idx_traffic_logs_account_id ON traffic_logs(account_id);
    ''')

    admin_count = db.execute('SELECT COUNT(*) FROM admin_users').fetchone()[0]
    if admin_count == 0:
        admin_user, admin_pass, _ = get_initial_admin_credentials()
        pw_hash = hash_password(admin_pass)
        db.execute(
            'INSERT OR IGNORE INTO admin_users (username, password_hash) VALUES (?, ?)',
            (admin_user, pw_hash)
        )
    db.commit()

    db.execute('BEGIN IMMEDIATE')
    account_columns = {row[1] for row in db.execute('PRAGMA table_info(accounts)')}
    for column, declaration in (
        ('sub_token', 'TEXT DEFAULT ""'),
        ('traffic_upload_bytes', 'INTEGER DEFAULT 0'),
        ('traffic_download_bytes', 'INTEGER DEFAULT 0'),
        ('expire_date', 'TEXT DEFAULT ""'),
    ):
        if column not in account_columns:
            db.execute(f'ALTER TABLE accounts ADD COLUMN {column} {declaration}')
    db.commit()

    db.close()
    try:
        database_path = Path(app.config['DATABASE'])
        if database_path.is_file():
            database_path.chmod(0o600)
    except OSError:
        pass

# ─── 订阅解析 ──────────────────────────────────────────────

_MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024
_SUBSCRIPTION_TIMEOUT_SECONDS = 10
_SUBSCRIPTION_READ_CHUNK = 64 * 1024
_SUBSCRIPTION_RESOLVER_CODE = (
    'import json, socket, sys\n'
    'try:\n'
    '    rows = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), '
    'type=socket.SOCK_STREAM)\n'
    'except socket.gaierror:\n'
    '    raise SystemExit(2)\n'
    "json.dump(sorted({row[4][0].split('%', 1)[0] for row in rows}), sys.stdout)\n"
)


def _subscription_remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('订阅拉取超时')
    return remaining


def _resolve_subscription_addresses(hostname, port, deadline):
    try:
        completed = subprocess.run(
            [
                sys.executable,
                '-I',
                '-c',
                _SUBSCRIPTION_RESOLVER_CODE,
                hostname,
                str(port),
            ],
            capture_output=True,
            text=True,
            timeout=_subscription_remaining_time(deadline),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError('订阅拉取超时') from None
    if completed.returncode != 0:
        raise ValueError("订阅地址无法解析")
    try:
        addresses = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("订阅地址解析结果无效") from None
    if not isinstance(addresses, list) or not all(
        isinstance(address, str) for address in addresses
    ):
        raise ValueError("订阅地址解析结果无效")
    return addresses


def _resolve_public_subscription_url(raw_url, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + _SUBSCRIPTION_TIMEOUT_SECONDS
    try:
        parsed = urlparse(raw_url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    except (TypeError, ValueError):
        raise ValueError("订阅地址必须是有效的 HTTP(S) URL") from None

    addresses = _resolve_subscription_addresses(
        parsed.hostname,
        port,
        deadline,
    )
    if not addresses:
        raise ValueError("订阅地址无法解析")

    validated_addresses = []
    for ip_text in addresses:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise ValueError("订阅地址解析结果无效") from exc
        allow_private = os.environ.get('ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS', '0') == '1'
        if not allow_private and not ip.is_global:
            raise ValueError("订阅地址必须指向公网 IP")
        if ip_text not in validated_addresses:
            validated_addresses.append(ip_text)
    return parsed, validated_addresses


def _assert_public_subscription_url(raw_url):
    _resolve_public_subscription_url(raw_url)
    return raw_url


def _subscription_request_target(parsed):
    target = parsed.path or '/'
    if parsed.params:
        target += f';{parsed.params}'
    if parsed.query:
        target += f'?{parsed.query}'
    return target


def _subscription_host_header(parsed):
    host = parsed.hostname
    if ':' in host:
        host = f'[{host}]'
    default_port = 443 if parsed.scheme == 'https' else 80
    return host if parsed.port in (None, default_port) else f'{host}:{parsed.port}'


def _set_subscription_socket_deadline(sock, deadline):
    remaining = _subscription_remaining_time(deadline)
    sock.settimeout(remaining)
    return remaining


def _read_subscription_body(response, sock, deadline):
    chunks = []
    size = 0
    while True:
        _set_subscription_socket_deadline(sock, deadline)
        chunk = response.read1(min(
            _SUBSCRIPTION_READ_CHUNK,
            _MAX_SUBSCRIPTION_BYTES + 1 - size,
        ))
        if not chunk:
            return b''.join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > _MAX_SUBSCRIPTION_BYTES:
            raise ValueError("订阅响应过大（最大 2 MiB）")


def _read_pinned_subscription_response(url, user_agent, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + _SUBSCRIPTION_TIMEOUT_SECONDS
    parsed, addresses = _resolve_public_subscription_url(url, deadline)

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    last_error = None
    for address in addresses:
        connection = None
        sock = None
        try:
            try:
                remaining = _subscription_remaining_time(deadline)
            except TimeoutError:
                break
            sock = socket.create_connection((address, port), timeout=remaining)
            if parsed.scheme == 'https':
                _set_subscription_socket_deadline(sock, deadline)
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            remaining = _set_subscription_socket_deadline(sock, deadline)

            connection = http.client.HTTPConnection(
                parsed.hostname,
                port,
                timeout=remaining,
            )
            connection.sock = sock
            connection.putrequest(
                'GET',
                _subscription_request_target(parsed),
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader('Host', _subscription_host_header(parsed))
            connection.putheader('User-Agent', user_agent)
            connection.putheader('Accept', '*/*')
            connection.putheader('Connection', 'close')
            _set_subscription_socket_deadline(sock, deadline)
            connection.endheaders()
            _set_subscription_socket_deadline(sock, deadline)
            response = connection.getresponse()

            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise OSError('订阅服务器返回了无 Location 的重定向')
                return None, urljoin(url, location)
            if not 200 <= response.status < 300:
                raise OSError(f'订阅服务器返回 HTTP {response.status}')

            raw = _read_subscription_body(response, sock, deadline)
            return raw, None
        except ValueError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            if connection is not None:
                connection.close()
            elif sock is not None:
                sock.close()

    raise OSError('订阅地址连接失败') from last_error


def _read_subscription_url(url, user_agent, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + _SUBSCRIPTION_TIMEOUT_SECONDS
    current_url = url
    for _ in range(6):
        raw, redirect_url = _read_pinned_subscription_response(
            current_url,
            user_agent,
            deadline,
        )
        if redirect_url is None:
            return raw
        current_url = redirect_url
    raise OSError('订阅重定向次数过多')


def parse_subscribe_url(url):
    """解析订阅链接，返回节点列表。支持:
    1. anytls://password@host:port?params#name  (单链接)
    2. base64 编码的多行订阅
    3. HTTP(S) URL 返回的订阅内容 (Clash YAML / 纯文本)
    """
    # HTTP URL 会按 User-Agent 返回不同格式，
    # 需要取样后选择最完整、AnyTLS 原生节点最多的结果。
    content = url.strip()
    traffic_info = {}
    if content.startswith('http://') or content.startswith('https://'):
        candidates = []
        deadline = time.monotonic() + _SUBSCRIPTION_TIMEOUT_SECONDS
        for ua in [
            'SSRVPN/2.4.0',
            'Clash.Meta/1.18.0',
            'Shadowrocket/2209 CFNetwork/1410.1 Darwin/22.6.0',
            'ClashForAndroid/2.5.12',
        ]:
            try:
                raw = _read_subscription_url(content, ua, deadline)
                text = _decode_subscription_response(raw)
                parsed_nodes = _parse_subscription_content(text)
                if parsed_nodes:
                    score = _subscription_candidate_score(parsed_nodes)
                    candidates.append((score, text, _extract_subscription_traffic_info(text)))
                    if score[0] > 0:
                        break
            except ValueError:
                raise
            except Exception:
                continue
        if not candidates:
            raise ValueError("拉取订阅失败（所有 UA 均无法访问）")
        _score, content, traffic_info = max(candidates, key=lambda item: item[0])

    nodes = _parse_subscription_content(content)
    if not nodes:
        preview = content[:100].replace('\n', ' ').replace('\r', '')
        raise ValueError(f"订阅中未找到可用节点 (内容前100字符: {preview})")
    return nodes, traffic_info


def _decode_subscription_response(raw):
    """Decode a subscription HTTP response to text when it is base64-wrapped."""
    text = raw.decode('utf-8', errors='ignore').strip()
    try:
        padded = text + '=' * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore').strip()
        if '://' in decoded or 'proxies:' in decoded:
            return decoded
    except Exception:
        pass
    return text


def _extract_subscription_traffic_info(content):
    for line in content.splitlines():
        if line.startswith('STATUS='):
            return _parse_status_line(line)
    return {}


def _subscription_candidate_score(nodes):
    anytls_count = 0
    for node in nodes:
        protocol = str(node.get('protocol', '')).lower().replace('-', '').replace('_', '')
        raw_uri = node.get('raw_uri', '')
        if protocol in ('anytls', 'anytls1') or raw_uri.startswith('anytls://'):
            anytls_count += 1
    return anytls_count, len(nodes)


def _parse_subscription_content(content):
    nodes = []

    # 尝试作为 Clash YAML 解析（最高优先级）
    clash_nodes = _parse_clash_yaml(content)
    if clash_nodes:
        return clash_nodes

    # 尝试 base64 解码后再解析
    try:
        padded = content + '=' * (-len(content) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
        if '://' in decoded or 'proxies:' in decoded:
            content = decoded
    except Exception:
        pass

    # 再次尝试 Clash YAML（base64 解码后可能是 YAML）
    clash_nodes = _parse_clash_yaml(content)
    if clash_nodes:
        return clash_nodes

    # 按行解析各种协议链接
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # 尝试 base64 解码单行
        try:
            padded = line + '=' * (-len(line) % 4)
            decoded_line = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if '://' in decoded_line:
                line = decoded_line
        except Exception:
            pass
        # 匹配所有支持的协议
        for scheme in ('anytls://', 'trojan://', 'vmess://', 'vless://', 'hysteria2://', 'hy2://', 'tuic://', 'ss://'):
            if line.startswith(scheme):
                node = parse_protocol_uri(line, scheme.rstrip(':/'))
                if node:
                    nodes.append(node)
                break

    return nodes


def _parse_status_line(line):
    """解析 STATUS= 行，提取流量信息
    格式: STATUS=🚀↑:0.4GB,↓:2.63GB,TOT:256GB💡Expires:2027-04-29
    """
    import re
    info = {}
    try:
        text = line.strip()
        # 提取上传
        m = re.search(r'↑[:\s]*([\d.]+)\s*(GB|MB|TB|KB)', text, re.IGNORECASE)
        if m:
            val, unit = float(m.group(1)), m.group(2).upper()
            multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
            info['upload_bytes'] = int(val * multipliers.get(unit, 1024**3))
            info['upload_display'] = f"{val}{unit}"
        # 提取下载
        m = re.search(r'↓[:\s]*([\d.]+)\s*(GB|MB|TB|KB)', text, re.IGNORECASE)
        if m:
            val, unit = float(m.group(1)), m.group(2).upper()
            multipliers = {'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
            info['download_bytes'] = int(val * multipliers.get(unit, 1024**3))
            info['download_display'] = f"{val}{unit}"
        # 提取总流量
        m = re.search(r'TOT[:\s]*([\d.]+)\s*(GB|MB|TB|KB)', text, re.IGNORECASE)
        if m:
            val, unit = float(m.group(1)), m.group(2).upper()
            info['total_gb'] = val if unit == 'GB' else val / 1024 if unit == 'MB' else val * 1024 if unit == 'TB' else val / 1024**3
            info['total_display'] = f"{val}{unit}"
        # 提取到期时间
        m = re.search(r'Expires[:\s]*(\d{4}-\d{2}-\d{2})', text, re.IGNORECASE)
        if m:
            info['expire_date'] = m.group(1)
        # 计算已用总量
        if 'upload_bytes' in info and 'download_bytes' in info:
            info['used_bytes'] = info['upload_bytes'] + info['download_bytes']
            info['used_display'] = format_bytes(info['used_bytes'])
    except Exception:
        pass
    return info


def _parse_clash_yaml(content):
    """从 Clash YAML 配置中提取节点（支持 anytls / trojan / vmess / vless / hysteria2 等）"""
    import yaml
    nodes = []
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return []
        proxies = data.get('proxies') or data.get('Proxy') or []
        if not isinstance(proxies, list):
            return []
        for p in proxies:
            try:
                if not isinstance(p, dict):
                    continue
                ptype = str(p.get('type', '')).lower().replace('-', '').replace('_', '')
                host = p.get('server', '')
                port = int(p.get('port', 443))
                password = p.get('password', '') or p.get('uuid', '')
                name = p.get('name', f"{host}:{port}")
                if not host or not 1 <= port <= 65535:
                    continue

                name_fragment = quote(str(name), safe='')

                def build_uri(scheme, credential, query):
                    authority_host = f'[{host}]' if ':' in str(host) else host
                    query_string = urlencode({
                        key: value for key, value in query.items()
                        if value is not None and value != ''
                    })
                    suffix = f'?{query_string}' if query_string else ''
                    return (
                        f"{scheme}://{quote(str(credential), safe='')}@"
                        f"{authority_host}:{port}{suffix}#{name_fragment}"
                    )

                ws_opts = p.get('ws-opts') if isinstance(p.get('ws-opts'), dict) else {}
                ws_headers = ws_opts.get('headers') if isinstance(ws_opts.get('headers'), dict) else {}
                grpc_opts = p.get('grpc-opts') if isinstance(p.get('grpc-opts'), dict) else {}
                reality_opts = p.get('reality-opts') if isinstance(p.get('reality-opts'), dict) else {}
                network = p.get('network', 'tcp') or 'tcp'
                servername = p.get('servername') or p.get('sni') or host
                insecure = '1' if p.get('skip-cert-verify') else '0'
                fingerprint = p.get('client-fingerprint') or p.get('fingerprint') or ''

                # 构建可供通用客户端使用、并能无损恢复关键 Clash 参数的 raw_uri。
                if ptype in ('anytls', 'anytls1'):
                    uri = build_uri('anytls', password, {
                        'security': 'tls',
                        'sni': servername,
                        'allowInsecure': insecure,
                        'fp': fingerprint,
                        'idleSessionCheckInterval': p.get('idle-session-check-interval'),
                        'idleSessionTimeout': p.get('idle-session-timeout'),
                        'minIdleSession': p.get('min-idle-session'),
                    })
                elif ptype == 'trojan':
                    uri = build_uri('trojan', password, {
                        'sni': servername,
                        'allowInsecure': insecure,
                        'fp': fingerprint,
                        'type': network,
                        'path': ws_opts.get('path', ''),
                        'host': ws_headers.get('Host', ''),
                        'serviceName': grpc_opts.get('grpc-service-name', ''),
                    })
                elif ptype == 'vmess':
                    import base64 as b64
                    vmess_obj = {"v": "2", "ps": name, "add": host, "port": str(port),
                                 "id": password, "aid": str(p.get('alterId', 0)),
                                 "scy": p.get('cipher', 'auto'),
                                 "net": network, "type": "none",
                                 "host": ws_headers.get('Host', ''),
                                 "path": ws_opts.get('path', ''),
                                 "serviceName": grpc_opts.get('grpc-service-name', ''),
                                 "tls": "tls" if p.get('tls') else "none",
                                 "sni": servername if p.get('tls') else "",
                                 "fp": fingerprint,
                                 "allowInsecure": insecure}
                    uri = "vmess://" + b64.urlsafe_b64encode(json.dumps(vmess_obj).encode()).decode().rstrip('=')
                elif ptype == 'vless':
                    uri = build_uri('vless', password, {
                        'security': 'reality' if reality_opts else ('tls' if p.get('tls') else 'none'),
                        'sni': servername,
                        'flow': p.get('flow', ''),
                        'type': network,
                        'path': ws_opts.get('path', ''),
                        'host': ws_headers.get('Host', ''),
                        'serviceName': grpc_opts.get('grpc-service-name', ''),
                        'allowInsecure': insecure,
                        'fp': fingerprint,
                        'encryption': p.get('encryption', ''),
                        'packetEncoding': p.get('packet-encoding', ''),
                        'pbk': reality_opts.get('public-key', ''),
                        'sid': reality_opts.get('short-id', ''),
                    })
                elif ptype in ('hysteria2', 'hy2', 'hysteria'):
                    uri = build_uri('hysteria2', password, {
                        'sni': servername,
                        'allowInsecure': insecure,
                        'obfs': p.get('obfs', ''),
                        'obfs-password': p.get('obfs-password', ''),
                    })
                elif ptype == 'tuic':
                    tuic_uuid = p.get('uuid', '')
                    uri = build_uri('tuic', f'{tuic_uuid}:{password}', {
                        'sni': servername,
                        'allowInsecure': insecure,
                    })
                elif ptype in ('ss', 'shadowsocks'):
                    method = p.get('cipher', 'aes-256-gcm')
                    import base64 as b64
                    if str(method).startswith('2022-blake3-'):
                        userinfo = f"{quote(str(method), safe='')}:{quote(str(password), safe='')}"
                    else:
                        userinfo = b64.urlsafe_b64encode(
                            f"{method}:{password}".encode()
                        ).decode().rstrip('=')
                    authority_host = f'[{host}]' if ':' in str(host) else host
                    ss_query = {}
                    if p.get('plugin'):
                        plugin_parts = [_sip002_escape(p['plugin'])]
                        if isinstance(p.get('plugin-opts'), dict):
                            for key, value in p['plugin-opts'].items():
                                if value is True:
                                    plugin_parts.append(_sip002_escape(key))
                                elif value not in (None, False):
                                    plugin_parts.append(
                                        f"{_sip002_escape(key)}={_sip002_escape(value)}"
                                    )
                        ss_query['plugin'] = ';'.join(plugin_parts)
                    query_suffix = f"/?{urlencode(ss_query)}" if ss_query else ''
                    uri = f"ss://{userinfo}@{authority_host}:{port}{query_suffix}#{name_fragment}"
                else:
                    # 其他类型也导入，保留原始信息
                    uri = build_uri(ptype, password, {})

                nodes.append({
                    'name': str(name),
                    'host': str(host),
                    'port': port,
                    'password': str(password),
                    'raw_uri': uri,
                    'protocol': 'shadowsocks' if ptype in ('ss', 'shadowsocks') else ptype,
                    'extra': {k: v for k, v in p.items() if k not in ('name', 'type', 'server', 'port', 'password')},
                })
            except (TypeError, ValueError):
                continue
    except Exception:
        pass
    return nodes


def parse_anytls_uri(uri):
    """兼容旧调用"""
    return parse_protocol_uri(uri, 'anytls')


def parse_protocol_uri(uri, protocol='anytls'):
    """通用协议 URI 解析，支持 anytls / trojan / vless / hysteria2 / tuic / ss"""
    try:
        uri = uri.strip()

        # vmess 特殊处理（base64 JSON）
        if protocol == 'vmess':
            import base64 as b64
            try:
                payload = uri.split('://', 1)[1]
                payload += '=' * (-len(payload) % 4)
                data = json.loads(b64.urlsafe_b64decode(payload).decode())
                return {
                    'name': data.get('ps', data.get('add', 'unknown')),
                    'host': data.get('add', ''),
                    'port': int(data.get('port', 443)),
                    'password': data.get('id', ''),
                    'raw_uri': uri,
                    'protocol': 'vmess',
                    'extra': data,
                }
            except Exception:
                return None

        # ss:// 特殊处理
        if protocol == 'ss':
            try:
                parsed = urlparse(uri)
                userinfo, separator, _hostport = parsed.netloc.rpartition('@')
                if separator:
                    import base64 as b64
                    try:
                        padded_userinfo = userinfo + '=' * (-len(userinfo) % 4)
                        userinfo = b64.urlsafe_b64decode(padded_userinfo).decode()
                    except Exception:
                        pass
                    method, password = map(unquote, userinfo.split(':', 1))
                    host = parsed.hostname
                    port = parsed.port
                    if not host or not port:
                        return None
                    return {
                        'name': unquote(parsed.fragment) if parsed.fragment else f"{host}:{port}",
                        'host': host,
                        'port': port,
                        'password': password,
                        'raw_uri': uri,
                        'protocol': 'shadowsocks',
                        'extra': {'cipher': method},
                    }
            except Exception:
                return None

        # 通用格式：scheme://password@host:port?params#name
        parsed = urlparse(uri)
        encoded_password, separator, _hostport = parsed.netloc.rpartition('@')
        if not separator or not parsed.hostname or parsed.port is None:
            return None
        password = unquote(encoded_password)
        host = parsed.hostname
        port = parsed.port
        params = parse_qs(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else f"{host}:{port}"

        return {
            'name': name,
            'host': host,
            'port': port,
            'password': password,
            'raw_uri': uri,
            'protocol': protocol,
            'extra': params,
        }
    except Exception:
        return None

# ─── 工具函数 ──────────────────────────────────────────────

def format_bytes(b):
    if b is None or b == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(b) < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} PB"

def calc_traffic_percent(used_bytes, limit_gb):
    if not limit_gb or limit_gb <= 0:
        return 0
    limit_bytes = limit_gb * 1024 * 1024 * 1024
    return min(round((used_bytes or 0) / limit_bytes * 100, 1), 100)


def days_until(expire_date):
    if not expire_date:
        return None
    try:
        target_date = datetime.strptime(str(expire_date), '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None
    return (target_date - datetime.now().date()).days


def parse_nonnegative_float(value, field_name):
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{field_name}必须是有效数字")
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{field_name}不能为负数")
    return parsed


def parse_nonnegative_int(value, field_name):
    if isinstance(value, bool):
        raise ValueError(f"{field_name}必须是非负整数")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field_name}必须是非负整数")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{field_name}必须是非负整数")
    if parsed < 0:
        raise ValueError(f"{field_name}不能为负数")
    return parsed


def _traffic_update_values(traffic_info):
    return tuple(traffic_info.get(key) for key in (
        'used_bytes',
        'upload_bytes',
        'download_bytes',
        'total_gb',
        'expire_date',
    ))


def sanitize_header_value(value, default="subscription"):
    cleaned = re.sub(r'[\r\n"\\]+', ' ', str(value or '')).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned[:120] or default

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_utils():
    return {
        'format_bytes': format_bytes,
        'calc_traffic_percent': calc_traffic_percent,
        'days_until': days_until,
        'now': datetime.now(),
    }

# ─── 认证 ──────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"], error_message="登录尝试过于频繁，请1分钟后再试")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            'SELECT * FROM admin_users WHERE username=?', (username,)
        ).fetchone()
        ok, needs_upgrade = (False, False)
        if user:
            ok, needs_upgrade = verify_password(user['password_hash'], password)
        if ok:
            if needs_upgrade:
                db.execute(
                    'UPDATE admin_users SET password_hash=? WHERE id=?',
                    (hash_password(password), user['id'])
                )
                db.commit()
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        flash('用户名或密码错误', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── 仪表盘 ──────────────────────────────────────────────

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    accounts = db.execute('SELECT * FROM accounts ORDER BY id').fetchall()

    total_accounts = len(accounts)
    active_accounts = sum(1 for a in accounts if a['status'] == 'active')
    total_nodes = sum(a['node_count'] or 0 for a in accounts)
    total_traffic_used = sum(a['traffic_used_bytes'] or 0 for a in accounts)
    total_traffic_limit = sum((a['traffic_limit_gb'] or 0) * 1024**3 for a in accounts)

    warning_accounts = []
    for a in accounts:
        pct = calc_traffic_percent(a['traffic_used_bytes'] or 0, a['traffic_limit_gb'] or 250)
        if pct >= 80:
            warning_accounts.append({**dict(a), 'usage_pct': pct})

    return render_template('dashboard.html',
        accounts=accounts,
        total_accounts=total_accounts,
        active_accounts=active_accounts,
        total_nodes=total_nodes,
        total_traffic_used=total_traffic_used,
        total_traffic_limit=total_traffic_limit,
        warning_accounts=warning_accounts,
    )

# ─── 账号管理 ──────────────────────────────────────────────

@app.route('/accounts')
@login_required
def accounts_list():
    db = get_db()
    accounts = db.execute('SELECT * FROM accounts ORDER BY id').fetchall()
    return render_template('accounts.html', accounts=accounts)

@app.route('/accounts/add', methods=['POST'])
@login_required
def account_add():
    name = request.form.get('name', '').strip()
    subscribe_url = request.form.get('subscribe_url', '').strip()
    traffic_limit = request.form.get('traffic_limit_gb', '250').strip()
    notes = request.form.get('notes', '').strip()

    if not subscribe_url:
        flash('请输入订阅链接', 'error')
        return redirect(url_for('accounts_list'))

    try:
        nodes, traffic_info = parse_subscribe_url(subscribe_url)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('accounts_list'))

    if not nodes:
        flash('未解析到节点', 'error')
        return redirect(url_for('accounts_list'))

    if not name:
        # 自动用第一个节点名作为账号名
        name = nodes[0]['name']

    # 用订阅返回的流量信息覆盖默认值
    if traffic_info.get('total_gb'):
        traffic_limit = traffic_info['total_gb']

    try:
        traffic_limit = parse_nonnegative_float(traffic_limit, '流量限制')
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('accounts_list'))

    db = get_db()
    cursor = db.execute(
        '''INSERT INTO accounts (
               name, subscribe_url, traffic_limit_gb, notes, node_count, last_synced_at,
               traffic_used_bytes, traffic_upload_bytes, traffic_download_bytes, expire_date
           ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)''',
        (
            name,
            subscribe_url,
            traffic_limit,
            notes,
            len(nodes),
            traffic_info.get('used_bytes', 0),
            traffic_info.get('upload_bytes', 0),
            traffic_info.get('download_bytes', 0),
            traffic_info.get('expire_date', ''),
        )
    )
    account_id = cursor.lastrowid

    # 保存到期时间到 notes（如果没有手动填 notes）
    if traffic_info.get('expire_date') and not notes:
        db.execute('UPDATE accounts SET notes=? WHERE id=?',
                   (f"到期: {traffic_info['expire_date']}", account_id))

    for n in nodes:
        db.execute(
            '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (
                account_id,
                n['name'],
                n['host'],
                n['port'],
                n['password'],
                n.get('raw_uri', ''),
                n.get('protocol', 'anytls'),
            )
        )
    db.commit()

    flash(f'账号 "{name}" 添加成功，已导入 {len(nodes)} 个节点', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<int:account_id>')
@login_required
def account_detail(account_id):
    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
    if not account:
        flash('账号不存在', 'error')
        return redirect(url_for('accounts_list'))

    nodes = db.execute(
        'SELECT * FROM nodes WHERE account_id=? ORDER BY id', (account_id,)
    ).fetchall()

    return render_template('account_detail.html', account=account, nodes=nodes)

@app.route('/accounts/<int:account_id>/rename', methods=['POST'])
@login_required
def account_rename(account_id):
    new_name = request.form.get('name', '').strip()
    if not new_name:
        flash('名称不能为空', 'error')
        return redirect(url_for('account_detail', account_id=account_id))

    db = get_db()
    db.execute(
        'UPDATE accounts SET name=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (new_name, account_id)
    )
    db.commit()
    flash(f'已重命名为 "{new_name}"', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<int:account_id>/edit', methods=['POST'])
@login_required
def account_edit(account_id):
    subscribe_url = request.form.get('subscribe_url', '').strip()
    traffic_limit = request.form.get('traffic_limit_gb', '250').strip()
    notes = request.form.get('notes', '').strip()
    status = request.form.get('status', 'active')

    try:
        traffic_limit = parse_nonnegative_float(traffic_limit, '流量限制')
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('account_detail', account_id=account_id))

    db = get_db()
    db.execute(
        '''UPDATE accounts SET subscribe_url=?, traffic_limit_gb=?, notes=?, status=?,
           updated_at=CURRENT_TIMESTAMP WHERE id=?''',
        (subscribe_url, traffic_limit, notes, status, account_id)
    )
    db.commit()
    flash('账号信息已更新', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<int:account_id>/delete', methods=['POST'])
@login_required
def account_delete(account_id):
    db = get_db()
    account = db.execute('SELECT name FROM accounts WHERE id=?', (account_id,)).fetchone()
    if account:
        db.execute('DELETE FROM traffic_logs WHERE account_id=?', (account_id,))
        db.execute('DELETE FROM traffic_collectors WHERE account_id=?', (account_id,))
        db.execute('DELETE FROM nodes WHERE account_id=?', (account_id,))
        db.execute('DELETE FROM accounts WHERE id=?', (account_id,))
        db.commit()
        flash(f'账号 "{account["name"]}" 已删除', 'success')
    return redirect(url_for('accounts_list'))

@app.route('/accounts/<int:account_id>/sync', methods=['POST'])
@login_required
def account_sync(account_id):
    """重新拉取订阅，同步节点"""
    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
    if not account:
        flash('账号不存在', 'error')
        return redirect(url_for('accounts_list'))

    try:
        nodes, traffic_info = parse_subscribe_url(account['subscribe_url'])
        if not nodes:
            raise ValueError('订阅中未找到可用节点')
    except ValueError as e:
        flash(f'同步失败: {e}', 'error')
        return redirect(url_for('account_detail', account_id=account_id))

    # 拉取发生在事务外；写入前重新确认账号仍存在，防止并发删除留下孤儿节点。
    db.execute('BEGIN IMMEDIATE')
    if not db.execute('SELECT 1 FROM accounts WHERE id=?', (account_id,)).fetchone():
        db.rollback()
        flash('账号已被删除，已取消同步', 'error')
        return redirect(url_for('accounts_list'))

    # 清除旧节点，重新插入
    db.execute('DELETE FROM nodes WHERE account_id=?', (account_id,))
    for n in nodes:
        db.execute(
            '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (
                account_id,
                n['name'],
                n['host'],
                n['port'],
                n['password'],
                n.get('raw_uri', ''),
                n.get('protocol', 'anytls'),
            )
        )
    db.execute(
        '''UPDATE accounts SET
               node_count=?,
               traffic_used_bytes=MAX(
                   COALESCE(traffic_used_bytes, 0),
                   COALESCE(?, traffic_used_bytes, 0)
               ),
               traffic_upload_bytes=COALESCE(?, traffic_upload_bytes),
               traffic_download_bytes=COALESCE(?, traffic_download_bytes),
               traffic_limit_gb=COALESCE(?, traffic_limit_gb),
               expire_date=COALESCE(?, expire_date),
               last_synced_at=CURRENT_TIMESTAMP,
               updated_at=CURRENT_TIMESTAMP
           WHERE id=?''',
        (len(nodes), *_traffic_update_values(traffic_info), account_id),
    )
    db.commit()
    flash(f'同步完成，更新了 {len(nodes)} 个节点', 'success')
    return redirect(url_for('account_detail', account_id=account_id))



# ─── 节点操作 ──────────────────────────────────────────────

@app.route('/nodes/monitor')
@login_required
def nodes_monitor():
    """节点检测页面 - 去重显示所有唯一节点"""
    db = get_db()
    # 按 host:port 去重，取每个唯一节点的最新状态
    nodes = db.execute('''
        WITH ranked AS (
            SELECT n.*,
                   ROW_NUMBER() OVER (
                       PARTITION BY n.host, n.port
                       ORDER BY (n.last_checked_at IS NOT NULL) DESC,
                                n.last_checked_at DESC, n.id DESC
                   ) AS row_number
            FROM nodes n
        ), account_counts AS (
            SELECT host, port, COUNT(DISTINCT account_id) AS account_count
            FROM nodes
            GROUP BY host, port
        )
        SELECT r.host, r.port, r.name, r.is_online, r.last_checked_at,
               r.protocol, r.raw_uri, r.password, r.latency_ms,
               c.account_count
        FROM ranked r
        JOIN account_counts c ON c.host = r.host AND c.port = r.port
        WHERE r.row_number = 1
        ORDER BY r.host, r.port
    ''').fetchall()
    return render_template('monitor.html', nodes=nodes)

@app.route('/nodes/<int:node_id>/delete', methods=['POST'])
@login_required
def node_delete(node_id):
    db = get_db()
    node = db.execute('SELECT * FROM nodes WHERE id=?', (node_id,)).fetchone()
    if node:
        db.execute('DELETE FROM nodes WHERE id=?', (node_id,))
        db.execute(
            'UPDATE accounts SET node_count = node_count - 1 WHERE id=?',
            (node['account_id'],)
        )
        db.commit()
        flash('节点已删除', 'success')
        return redirect(url_for('account_detail', account_id=node['account_id']))
    flash('节点不存在', 'error')
    return redirect(url_for('accounts_list'))

# ─── API 流量上报（豁免 CSRF，供外部脚本调用）──────────────────


def _resolve_traffic_account_id(db, item):
    if 'account_id' in item:
        try:
            account_id = parse_nonnegative_int(item['account_id'], 'account_id')
        except ValueError as exc:
            return None, str(exc), 400
        if account_id < 1:
            return None, 'account_id must be a positive integer', 400
        return account_id, None, None

    password = item.get('password')
    if not password and item.get('password_b64'):
        try:
            password = base64.b64decode(
                item['password_b64'], validate=True
            ).decode('utf-8')
        except (ValueError, TypeError, UnicodeDecodeError):
            return None, 'invalid password_b64', 400
    if not password:
        return None, 'account not found', 404

    matches = db.execute(
        'SELECT DISTINCT account_id FROM nodes WHERE password=? LIMIT 2',
        (password,),
    ).fetchall()
    if not matches:
        return None, 'account not found', 404
    if len(matches) > 1:
        return None, 'ambiguous password; use account_id', 409
    return matches[0]['account_id'], None, None


@app.route('/api/traffic/report', methods=['POST'])
@csrf.exempt
@limiter.limit("60 per minute")
@require_traffic_api_token
def api_report_traffic():
    """上报流量: {"account_id": 1, "bytes_used": 123} 或 {"password": "xxx", ...}"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        return jsonify({"error": "Invalid JSON"}), 400

    db = get_db()
    results = []
    for item in data:
        if not isinstance(item, dict):
            return jsonify({"error": "Invalid traffic item"}), 400
        try:
            bytes_used = parse_nonnegative_int(item.get('bytes_used', 0), 'bytes_used')
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        account_id, identity_error, identity_status = _resolve_traffic_account_id(db, item)
        if identity_error:
            return jsonify({"error": identity_error}), identity_status

        cursor = db.execute(
            'UPDATE accounts SET traffic_used_bytes=COALESCE(traffic_used_bytes, 0) + ?, '
            'updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (bytes_used, account_id)
        )
        if cursor.rowcount == 0:
            results.append({"status": "error", "msg": "account not found"})
            continue
        account = db.execute(
            'SELECT traffic_used_bytes FROM accounts WHERE id=?',
            (account_id,)
        ).fetchone()
        new_total = account['traffic_used_bytes']
        db.execute(
            'INSERT INTO traffic_logs (account_id, bytes_used) VALUES (?, ?)',
            (account_id, bytes_used)
        )
        results.append({"account_id": account_id, "status": "ok", "total_bytes": new_total})

    db.commit()
    return jsonify({"results": results})


@app.route('/api/traffic/counter', methods=['POST'])
@csrf.exempt
@limiter.limit("60 per minute")
@require_traffic_api_token
def api_report_traffic_counter():
    """Idempotently ingest one collector's cumulative raw byte counter."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    collector_id = str(data.get('collector_id', ''))
    if not re.fullmatch(r'[A-Za-z0-9._:-]{8,128}', collector_id):
        return jsonify({"error": "invalid collector_id"}), 400
    try:
        counter_bytes = parse_nonnegative_int(
            data.get('counter_bytes'), 'counter_bytes'
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    db = get_db()
    db.execute('BEGIN IMMEDIATE')
    account_id, identity_error, identity_status = _resolve_traffic_account_id(db, data)
    if identity_error:
        db.rollback()
        return jsonify({"error": identity_error}), identity_status

    previous = db.execute(
        'SELECT account_id, last_counter_bytes FROM traffic_collectors '
        'WHERE collector_id=?',
        (collector_id,),
    ).fetchone()
    if previous and previous['account_id'] != account_id:
        db.rollback()
        return jsonify({"error": "collector_id belongs to another account"}), 409

    previous_bytes = previous['last_counter_bytes'] if previous else counter_bytes
    delta_bytes = 0 if not previous else (
        counter_bytes - previous_bytes
        if counter_bytes >= previous_bytes
        else counter_bytes
    )
    cursor = db.execute(
        'UPDATE accounts SET traffic_used_bytes=COALESCE(traffic_used_bytes, 0) + ?, '
        'updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (delta_bytes, account_id),
    )
    if cursor.rowcount == 0:
        db.rollback()
        return jsonify({"error": "account not found"}), 404

    if previous:
        db.execute(
            'UPDATE traffic_collectors SET last_counter_bytes=?, '
            'updated_at=CURRENT_TIMESTAMP WHERE collector_id=?',
            (counter_bytes, collector_id),
        )
    else:
        db.execute(
            'INSERT INTO traffic_collectors '
            '(collector_id, account_id, last_counter_bytes) VALUES (?, ?, ?)',
            (collector_id, account_id, counter_bytes),
        )
    account = db.execute(
        'SELECT traffic_used_bytes FROM accounts WHERE id=?', (account_id,)
    ).fetchone()
    db.commit()
    return jsonify({
        "status": "ok",
        "account_id": account_id,
        "delta_bytes": delta_bytes,
        "total_bytes": account['traffic_used_bytes'],
    })

@app.route('/api/traffic/set', methods=['POST'])
@csrf.exempt
@limiter.limit("60 per minute")
@require_traffic_api_token
def api_set_traffic():
    """设置流量绝对值: {"account_id": 1, "total_bytes": 999}"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        total_bytes = parse_nonnegative_int(data.get('total_bytes', 0), 'total_bytes')
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    db = get_db()
    account_id, identity_error, identity_status = _resolve_traffic_account_id(db, data)
    if identity_error:
        return jsonify({"error": identity_error}), identity_status

    cursor = db.execute(
        'UPDATE accounts SET traffic_used_bytes=MAX(COALESCE(traffic_used_bytes, 0), ?), '
        'updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (total_bytes, account_id)
    )
    if cursor.rowcount == 0:
        return jsonify({"error": "account not found"}), 404
    account = db.execute(
        'SELECT traffic_used_bytes FROM accounts WHERE id=?', (account_id,)
    ).fetchone()
    db.commit()
    return jsonify({"status": "ok", "total_bytes": account['traffic_used_bytes']})

@app.route('/api/accounts')
@login_required
def api_accounts():
    db = get_db()
    accounts = db.execute('SELECT * FROM accounts ORDER BY id').fetchall()
    return jsonify([dict(a) for a in accounts])

@app.route('/api/accounts/<int:account_id>/nodes')
@login_required
def api_account_nodes(account_id):
    db = get_db()
    nodes = db.execute('SELECT * FROM nodes WHERE account_id=? ORDER BY id', (account_id,)).fetchall()
    return jsonify([dict(n) for n in nodes])

@app.route('/api/check-by-host', methods=['POST'])
@login_required
def api_check_by_host():
    """按 host:port 检测节点，并更新所有匹配节点的状态"""
    data = request.get_json(silent=True)
    if not data or not data.get('host') or not data.get('port'):
        return jsonify({"error": "missing host/port"}), 400

    host = data['host']
    try:
        port = parse_nonnegative_int(data['port'], 'port')
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not 1 <= port <= 65535:
        return jsonify({"error": "port必须在1-65535之间"}), 400

    result = _check_node_connect(host, port)
    db = get_db()
    db.execute(
        'UPDATE nodes SET is_online=?, last_checked_at=CURRENT_TIMESTAMP, latency_ms=? WHERE host=? AND port=?',
        (1 if result['online'] else 0, result.get('latency', -1), host, port)
    )
    db.commit()
    return jsonify(result)

@app.route('/api/nodes/<int:node_id>/check', methods=['POST'])
@login_required
def api_check_node(node_id):
    import socket
    import ssl
    db = get_db()
    node = db.execute('SELECT * FROM nodes WHERE id=?', (node_id,)).fetchone()
    if not node:
        return jsonify({"error": "not found"}), 404

    try:
        result = _check_node_connect(node['host'], node['port'])
        db.execute(
            'UPDATE nodes SET is_online=?, last_checked_at=CURRENT_TIMESTAMP, latency_ms=? WHERE id=?',
            (1 if result['online'] else 0, result.get('latency', -1), node_id)
        )
        db.commit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@app.route('/api/accounts/<int:account_id>/check-all', methods=['POST'])
@login_required
def api_check_all_nodes(account_id):
    db = get_db()
    nodes = [dict(node) for node in db.execute(
        'SELECT * FROM nodes WHERE account_id=?', (account_id,)
    ).fetchall()]

    def check(node):
        try:
            return node, _check_node_connect(node['host'], node['port']), None
        except Exception as e:
            return node, None, str(e)

    results = []
    checks = _bounded_parallel_map(check, nodes, max_workers=32)
    for node, r, error in checks:
        if error is None:
            latency = r.get('latency', -1)
            db.execute(
                'UPDATE nodes SET is_online=?, last_checked_at=CURRENT_TIMESTAMP, latency_ms=? WHERE id=?',
                (1 if r['online'] else 0, latency, node['id'])
            )
            results.append({
                "node_id": node['id'],
                "name": node['name'],
                "online": r['online'],
                "msg": r['msg'],
                "latency": latency,
            })
        else:
            results.append({"node_id": node['id'], "name": node['name'], "online": False, "msg": error, "latency": -1})
    db.commit()
    return jsonify({"results": results})


def _bounded_parallel_map(function, items, max_workers=8):
    """Run blocking network work concurrently while keeping DB writes in the caller."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as executor:
        return list(executor.map(function, items))

def _check_node_connect(host, port, timeout=8):
    """通过 TLS CONNECT 检测节点可用性，返回延迟"""
    import socket
    import ssl
    import time
    sock = None
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        # 尝试 TLS 握手
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        tls_sock.close()
        latency = int((time.time() - start) * 1000)
        return {"online": True, "status": "online", "msg": "TLS 连接成功", "latency": latency}
    except ssl.SSLError:
        latency = int((time.time() - start) * 1000)
        return {"online": True, "status": "online", "msg": "TCP 连接成功 (TLS 异常)", "latency": latency}
    except socket.timeout:
        return {"online": False, "status": "offline", "msg": "连接超时", "latency": -1}
    except ConnectionRefusedError:
        return {"online": False, "status": "offline", "msg": "连接被拒绝", "latency": -1}
    except Exception as e:
        return {"online": False, "status": "offline", "msg": str(e), "latency": -1}
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass

@app.route('/api/sync-all', methods=['POST'])
@login_required
def api_sync_all():
    """一键同步所有账号的订阅"""
    db = get_db()
    accounts = [dict(account) for account in db.execute(
        "SELECT * FROM accounts WHERE status='active' ORDER BY id"
    ).fetchall()]

    def fetch(account):
        try:
            nodes, traffic_info = parse_subscribe_url(account['subscribe_url'])
            return account, nodes, traffic_info, None
        except Exception as e:
            return account, None, None, str(e)

    results = []
    fetched_accounts = _bounded_parallel_map(fetch, accounts)
    db.execute('BEGIN IMMEDIATE')
    for account, nodes, traffic_info, error in fetched_accounts:
        if error is None:
            if not db.execute(
                'SELECT 1 FROM accounts WHERE id=?', (account['id'],)
            ).fetchone():
                results.append({
                    "id": account['id'],
                    "name": account['name'],
                    "status": "skipped",
                    "msg": "account was deleted during sync",
                })
                continue
            if not nodes:
                results.append({
                    "id": account['id'],
                    "name": account['name'],
                    "status": "error",
                    "msg": "订阅中未找到可用节点",
                })
                continue
            db.execute('DELETE FROM nodes WHERE account_id=?', (account['id'],))
            for n in nodes:
                db.execute(
                    '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri, protocol)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (
                        account['id'],
                        n['name'],
                        n['host'],
                        n['port'],
                        n['password'],
                        n.get('raw_uri', ''),
                        n.get('protocol', 'anytls'),
                    )
                )
            db.execute(
                '''UPDATE accounts SET
                       node_count=?,
                       traffic_used_bytes=MAX(
                           COALESCE(traffic_used_bytes, 0),
                           COALESCE(?, traffic_used_bytes, 0)
                       ),
                       traffic_upload_bytes=COALESCE(?, traffic_upload_bytes),
                       traffic_download_bytes=COALESCE(?, traffic_download_bytes),
                       traffic_limit_gb=COALESCE(?, traffic_limit_gb),
                       expire_date=COALESCE(?, expire_date),
                       last_synced_at=CURRENT_TIMESTAMP,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE id=?''',
                (len(nodes), *_traffic_update_values(traffic_info), account['id']),
            )
            results.append({"id": account['id'], "name": account['name'], "status": "ok", "nodes": len(nodes)})
        else:
            results.append({"id": account['id'], "name": account['name'], "status": "error", "msg": error})
    db.commit()
    return jsonify({"results": results})

@app.route('/api/subscribe')
@login_required
def api_subscribe():
    """获取所有活跃账号的节点订阅"""
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE status='active' ORDER BY id").fetchall()
    links = []
    for a in accounts:
        nodes = db.execute('SELECT * FROM nodes WHERE account_id=?', (a['id'],)).fetchall()
        for n in nodes:
            if n['raw_uri']:
                links.append(n['raw_uri'])
    return jsonify({"links": links, "count": len(links)})

@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    old_pw = request.form.get('old_password', '')
    new_pw = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')

    if new_pw != confirm_pw:
        flash('两次输入的新密码不一致', 'error')
        return redirect(url_for('dashboard'))
    if not 8 <= len(new_pw) <= 128:
        flash('密码必须为8-128个字符', 'error')
        return redirect(url_for('dashboard'))

    db = get_db()
    user = db.execute(
        'SELECT * FROM admin_users WHERE username=?',
        (session.get('username', 'admin'),)
    ).fetchone()
    if not user or not verify_password(user['password_hash'], old_pw)[0]:
        flash('原密码错误', 'error')
        return redirect(url_for('dashboard'))

    new_hash = hash_password(new_pw)
    db.execute('UPDATE admin_users SET password_hash=? WHERE id=?', (new_hash, user['id']))
    db.commit()
    flash('密码修改成功', 'success')
    return redirect(url_for('dashboard'))

# ─── 订阅转换（二次转链）──────────────────────────────────────

def _get_rename_rules():
    """获取所有启用的重命名规则"""
    db = get_db()
    return db.execute('SELECT old_text, new_text FROM rename_rules WHERE enabled=1 ORDER BY id').fetchall()


def _apply_rename(text, rules):
    """对文本应用重命名规则"""
    for r in rules:
        text = text.replace(r['old_text'], r['new_text'])
    return text


def _row_get(row, key, default=None):
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        return default


def _account_traffic_info(account):
    info = {}
    used_bytes = _row_get(account, 'traffic_used_bytes', 0) or 0
    upload_bytes = _row_get(account, 'traffic_upload_bytes', 0) or 0
    download_bytes = _row_get(account, 'traffic_download_bytes', 0) or 0
    total_gb = _row_get(account, 'traffic_limit_gb', 0) or 0
    expire_date = _row_get(account, 'expire_date', '') or ''
    if upload_bytes:
        info['upload_bytes'] = int(upload_bytes)
    if download_bytes:
        info['download_bytes'] = int(download_bytes)
    elif used_bytes and not upload_bytes:
        info['download_bytes'] = int(used_bytes)
    if total_gb:
        info['total_gb'] = float(total_gb)
    if expire_date:
        info['expire_date'] = expire_date
    return info


def _nodes_from_db_rows(db_nodes):
    return [
        {'raw_uri': n['raw_uri'], 'name': n['name']}
        for n in db_nodes
        if n['raw_uri']
    ]


def _query_value(params, *names, default=''):
    for name in names:
        values = params.get(name)
        if values:
            return values[0]
    return default


def _sip002_escape(value):
    escaped = str(value).replace('\\', '\\\\')
    for char in (':', ';', '='):
        escaped = escaped.replace(char, f'\\{char}')
    return escaped


def _sip002_split(value, separator, maxsplit=-1):
    parts = []
    current = []
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


def _is_true(value):
    return str(value).lower() in ('1', 'true', 'yes')


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _clash_proxy_from_uri(uri):
    scheme = uri.split('://', 1)[0].lower()
    protocol = 'ss' if scheme == 'ss' else scheme
    node = parse_protocol_uri(uri, protocol)
    if not node:
        return None

    proxy = {'name': node['name'], 'server': node['host'], 'port': node['port']}
    params = parse_qs(urlparse(uri).query)
    p = node['protocol']
    if p in ('anytls', 'anytls1'):
        allow_insecure = _query_value(
            params,
            'allowInsecure',
            'allow-insecure',
            'insecure',
            default='0',
        )
        proxy.update({
            'type': 'anytls',
            'password': node['password'],
            'udp': True,
            'sni': _query_value(params, 'sni', default=node['host']) or node['host'],
            'skip-cert-verify': _is_true(allow_insecure),
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
    elif p == 'vmess':
        extra = node.get('extra', {})
        proxy.update({
            'type': 'vmess',
            'uuid': node['password'],
            'alterId': _safe_int(extra.get('aid', 0) or 0),
            'cipher': extra.get('scy', 'auto') or 'auto',
        })
        network = extra.get('net', 'tcp') or 'tcp'
        if network != 'tcp':
            proxy['network'] = network
        if str(extra.get('tls', '')).lower() in ('tls', '1', 'true'):
            proxy['tls'] = True
        if extra.get('sni'):
            proxy['servername'] = extra['sni']
        if _is_true(extra.get('allowInsecure', '0')):
            proxy['skip-cert-verify'] = True
        if extra.get('fp'):
            proxy['client-fingerprint'] = extra['fp']
        if network == 'ws':
            ws_opts = {'path': extra.get('path', '') or '/'}
            if extra.get('host'):
                ws_opts['headers'] = {'Host': extra['host']}
            proxy['ws-opts'] = ws_opts
        elif network == 'grpc' and extra.get('serviceName'):
            proxy['grpc-opts'] = {'grpc-service-name': extra['serviceName']}
    elif p == 'shadowsocks':
        proxy.update({
            'type': 'ss',
            'cipher': node.get('extra', {}).get('cipher', 'aes-256-gcm'),
            'password': node['password'],
        })
        plugin_argument = _query_value(params, 'plugin')
        if plugin_argument:
            plugin_parts = _sip002_split(plugin_argument, ';')
            proxy['plugin'] = _sip002_unescape(plugin_parts[0])
            plugin_opts = {}
            for option in plugin_parts[1:]:
                key_value = _sip002_split(option, '=', maxsplit=1)
                if len(key_value) == 2:
                    key, value = map(_sip002_unescape, key_value)
                    plugin_opts[key] = value
                elif option:
                    plugin_opts[_sip002_unescape(option)] = True
            if plugin_opts:
                proxy['plugin-opts'] = plugin_opts
        encoded_plugin_opts = _query_value(params, 'pluginOpts')
        if encoded_plugin_opts and 'plugin-opts' not in proxy:
            try:
                encoded_plugin_opts += '=' * (-len(encoded_plugin_opts) % 4)
                proxy['plugin-opts'] = json.loads(
                    base64.urlsafe_b64decode(encoded_plugin_opts).decode()
                )
            except (ValueError, TypeError, UnicodeDecodeError):
                pass
    else:
        proxy['type'] = 'hysteria2' if p in ('hysteria2', 'hy2') else p
        if p == 'tuic' and ':' in node['password']:
            tuic_uuid, tuic_password = node['password'].split(':', 1)
            proxy['uuid'] = tuic_uuid
            proxy['password'] = tuic_password
        else:
            credential_field = 'uuid' if p == 'vless' else 'password'
            proxy[credential_field] = node['password']
        sni = _query_value(params, 'sni', 'peer', default=node['host']) or node['host']
        if p == 'vless':
            proxy['servername'] = sni
        elif p in ('trojan', 'hysteria2', 'hy2', 'tuic'):
            proxy['sni'] = sni
        allow_insecure = _query_value(
            params,
            'allowInsecure',
            'allow-insecure',
            'insecure',
            default='0',
        )
        if p in ('trojan', 'vless', 'hysteria2', 'hy2', 'tuic'):
            proxy['skip-cert-verify'] = _is_true(allow_insecure)
        if p == 'vless' and _query_value(params, 'security') in ('tls', 'reality'):
            proxy['tls'] = True
        if p == 'vless' and _query_value(params, 'security') == 'reality':
            public_key = _query_value(params, 'pbk')
            short_id = _query_value(params, 'sid')
            if public_key or short_id:
                proxy['reality-opts'] = {}
                if public_key:
                    proxy['reality-opts']['public-key'] = public_key
                if short_id:
                    proxy['reality-opts']['short-id'] = short_id
        flow = _query_value(params, 'flow')
        if p == 'vless' and flow:
            proxy['flow'] = flow
        network = _query_value(params, 'type', 'network')
        if network:
            proxy['network'] = network
        fingerprint = _query_value(params, 'fp')
        if p in ('trojan', 'vless') and fingerprint:
            proxy['client-fingerprint'] = fingerprint
        if p in ('trojan', 'vless') and network == 'ws':
            ws_opts = {'path': _query_value(params, 'path', default='/') or '/'}
            ws_host = _query_value(params, 'host')
            if ws_host:
                ws_opts['headers'] = {'Host': ws_host}
            proxy['ws-opts'] = ws_opts
        elif p in ('trojan', 'vless') and network == 'grpc':
            service_name = _query_value(params, 'serviceName')
            if service_name:
                proxy['grpc-opts'] = {'grpc-service-name': service_name}
        if p == 'vless':
            packet_encoding = _query_value(params, 'packetEncoding', 'packet-encoding')
            if packet_encoding:
                proxy['packet-encoding'] = packet_encoding
            encryption = _query_value(params, 'encryption')
            if encryption:
                proxy['encryption'] = encryption
        if p in ('hysteria2', 'hy2'):
            obfs = _query_value(params, 'obfs')
            obfs_password = _query_value(params, 'obfs-password')
            if obfs:
                proxy['obfs'] = obfs
            if obfs_password:
                proxy['obfs-password'] = obfs_password
    return proxy


@app.route('/sub/<token>')
@csrf.exempt
@limiter.limit("120 per minute")
def public_subscribe(token):
    """公开订阅端点：只读取最后一次成功同步到本地的节点。"""
    if not token:
        return 'Invalid token', 404

    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE sub_token=? AND status='active'",
        (token,),
    ).fetchone()
    if not account:
        return 'Not found', 404

    rules = db.execute('SELECT old_text, new_text FROM rename_rules WHERE enabled=1 ORDER BY id').fetchall()

    db_nodes = db.execute('SELECT * FROM nodes WHERE account_id=? ORDER BY id', (account['id'],)).fetchall()
    nodes = _nodes_from_db_rows(db_nodes)
    traffic_info = _account_traffic_info(account)
    if not nodes:
        return 'Subscription data is not ready', 503, {
            'Retry-After': '60',
            'Cache-Control': 'no-store',
        }

    # 构建订阅配置名称（profile-title）
    sub_name = 'SSRVPN.VIP'  # 默认名
    if rules:
        sub_name = _apply_rename(sub_name, rules)
    header_sub_name = sanitize_header_value(sub_name, 'SSRVPN.VIP')

    # 公共响应头：profile-title 设置订阅名 + 流量信息
    resp_headers = {
        'profile-title': f'"store-name={header_sub_name}"',
        'Content-Disposition': f'attachment; filename="{header_sub_name}"',
    }
    if traffic_info:
        parts = []
        if traffic_info.get('upload_bytes'):
            parts.append(f"upload={traffic_info['upload_bytes']}")
        if traffic_info.get('download_bytes'):
            parts.append(f"download={traffic_info['download_bytes']}")
        if traffic_info.get('total_gb'):
            parts.append(f"total={int(traffic_info['total_gb'] * 1024**3)}")
        if traffic_info.get('expire_date'):
            from datetime import datetime
            try:
                ts = int(datetime.strptime(traffic_info['expire_date'], '%Y-%m-%d').timestamp())
                parts.append(f"expire={ts}")
            except Exception:
                pass
        if parts:
            resp_headers['Subscription-Userinfo'] = '; '.join(parts)

    ua = request.headers.get('User-Agent', '')

    lines = [n.get('raw_uri', '') for n in nodes if n.get('raw_uri', '')]

    # 根据 User-Agent 返回不同格式
    content = '\n'.join(lines)

    if 'Clash' in ua or 'clash' in ua:
        # 返回 Clash YAML
        proxies = [proxy for line in lines if (proxy := _clash_proxy_from_uri(line))]

        import yaml
        clash_config = {'proxies': proxies}
        resp_headers['Content-Type'] = 'text/yaml; charset=utf-8'
        return yaml.dump(clash_config, allow_unicode=True, default_flow_style=False), 200, resp_headers

    # 默认返回 base64 编码（Shadowrocket / 通用格式）
    b64 = base64.b64encode(content.encode()).decode()
    resp_headers['Content-Type'] = 'text/plain; charset=utf-8'
    return b64, 200, resp_headers


@app.route('/api/accounts/<int:account_id>/generate-token', methods=['POST'])
@login_required
def api_generate_token(account_id):
    """为账号生成/重新生成分享 token"""
    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
    if not account:
        return jsonify({"error": "not found"}), 404

    token = secrets.token_hex(16)
    db.execute('UPDATE accounts SET sub_token=? WHERE id=?', (token, account_id))
    db.commit()
    return jsonify({"token": token, "url": url_for('public_subscribe', token=token, _external=True)})


@app.route('/settings/rename-rules')
@login_required
def rename_rules_page():
    db = get_db()
    rules = db.execute('SELECT * FROM rename_rules ORDER BY id').fetchall()
    return render_template('rename_rules.html', rules=rules)


@app.route('/settings/rename-rules/add', methods=['POST'])
@login_required
def rename_rule_add():
    old_text = request.form.get('old_text', '').strip()
    new_text = request.form.get('new_text', '').strip()
    if not old_text:
        flash('原名称不能为空', 'error')
        return redirect(url_for('rename_rules_page'))
    db = get_db()
    db.execute('INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)', (old_text, new_text))
    db.commit()
    flash(f'规则已添加：{old_text} → {new_text}', 'success')
    return redirect(url_for('rename_rules_page'))


@app.route('/settings/rename-rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def rename_rule_toggle(rule_id):
    db = get_db()
    db.execute('UPDATE rename_rules SET enabled = 1 - enabled WHERE id=?', (rule_id,))
    db.commit()
    return redirect(url_for('rename_rules_page'))


@app.route('/settings/rename-rules/<int:rule_id>/delete', methods=['POST'])
@login_required
def rename_rule_delete(rule_id):
    db = get_db()
    db.execute('DELETE FROM rename_rules WHERE id=?', (rule_id,))
    db.commit()
    flash('规则已删除', 'success')
    return redirect(url_for('rename_rules_page'))


# ─── 初始化 & 启动 ─────────────────────────────────────


def _development_server_options():
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 8866))
    debug = _env_flag('DEBUG')
    is_loopback = host == 'localhost'
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = False
    if debug and not is_loopback:
        raise RuntimeError('Flask debug mode may only bind to a loopback address')
    return host, port, debug


init_db()

if __name__ == '__main__':
    host, port, debug = _development_server_options()
    print(f"\n  AnyTLS Panel running at http://{host}:{port}")
    if app.config.get('INITIAL_ADMIN_PASSWORD_FILE'):
        print(f"  Initial admin user: admin")
        print(f"  Initial password file: {app.config['INITIAL_ADMIN_PASSWORD_FILE']}\n")
    app.run(host=host, port=port, debug=debug)
