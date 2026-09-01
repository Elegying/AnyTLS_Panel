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
import logging
import socket
import ssl
import http.client
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps
from urllib.parse import urljoin, urlparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, g, has_request_context
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from db_migrations import SCHEMA_VERSION, apply_schema_migrations
from database_maintenance import (
    checkpoint_database,
    database_metrics,
    prune_traffic_logs,
)
from input_limits import (
    DEFAULT_MAX_REQUEST_BYTES,
    MAX_HOST_CHARS,
    MAX_NAME_CHARS,
    MAX_NOTES_CHARS,
    MAX_RENAME_TEXT_CHARS,
    MAX_SUBSCRIPTION_TEXT_CHARS,
    MAX_TRAFFIC_BATCH_ITEMS,
    SQLITE_INTEGER_MAX,
    bounded_env_int,
    validate_text,
)
from protocol_codecs import (
    clash_proxy_from_uri as _clash_proxy_from_uri,
    parse_clash_yaml as _parse_clash_yaml,
    parse_protocol_uri,
)
from security_utils import hash_password, verify_password
from sqlite_rate_limit import enforce_rate_limit, rate_limit
from traffic_token import make_account_traffic_token
from node_probe import check_node_connect


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
app.config['SESSION_REFRESH_EACH_REQUEST'] = False
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token 1小时有效
app.config['MAX_CONTENT_LENGTH'] = bounded_env_int(
    'ANYTLS_MAX_REQUEST_BYTES',
    DEFAULT_MAX_REQUEST_BYTES,
    64 * 1024,
    16 * 1024 * 1024,
)
app.config['MAX_FORM_MEMORY_SIZE'] = app.config['MAX_CONTENT_LENGTH']

if _env_flag('ANYTLS_TRUST_PROXY'):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# CSRF 保护
csrf = CSRFProtect(app)

audit_logger = logging.getLogger('anytls.audit')
_REQUEST_ID_PATTERN = re.compile(r'^[A-Za-z0-9._:-]{1,64}$')
_AUDIT_DETAIL_FIELDS = {
    'account_id', 'node_count', 'node_id', 'rule_id', 'status', 'username', 'reason'
}
_READINESS_MIN_FREE_BYTES = 64 * 1024 * 1024


def audit_event(action, outcome, **details):
    payload = {
        'event': 'audit',
        'action': action,
        'outcome': outcome,
    }
    if has_request_context():
        payload['request_id'] = getattr(g, 'request_id', '')
        payload['remote_addr'] = request.remote_addr or ''
    payload.update({
        key: value for key, value in details.items()
        if key in _AUDIT_DETAIL_FIELDS
    })
    payload = {
        key: value.replace('\r', '').replace('\n', '')
        if isinstance(value, str) else value
        for key, value in payload.items()
    }
    audit_logger.info('%s', json.dumps(
        payload,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True,
    ))


@app.before_request
def assign_request_id():
    supplied = request.headers.get('X-Request-ID', '')
    g.request_id = (
        supplied if _REQUEST_ID_PATTERN.fullmatch(supplied)
        else secrets.token_hex(16)
    )
    g.csp_nonce = secrets.token_urlsafe(18)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    nonce = getattr(g, 'csp_nonce', secrets.token_urlsafe(18))
    response.headers['Content-Security-Policy'] = '; '.join((
        "default-src 'self'",
        f"script-src 'self' 'nonce-{nonce}'",
        "script-src-attr 'none'",
        f"style-src 'self' 'nonce-{nonce}'",
        "style-src-attr 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    ))
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['X-Request-ID'] = getattr(g, 'request_id', secrets.token_hex(16))
    if request.endpoint != 'static':
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.errorhandler(413)
def request_too_large(_error):
    audit_event('request.rejected', 'failure', reason='payload_too_large')
    if request.path.startswith('/api/'):
        return jsonify({'error': 'request payload is too large'}), 413
    return '请求内容过大', 413


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


@app.before_request
def enforce_default_request_limit():
    if request.endpoint in {'healthz', 'readyz'}:
        return None
    view = app.view_functions.get(request.endpoint)
    if view is not None and getattr(view, '_sqlite_rate_limit', False):
        return None
    return enforce_rate_limit(
        get_db,
        "global",
        200,
        60,
        "请求过于频繁，请稍后再试",
    )


def _is_loopback_request():
    try:
        return ipaddress.ip_address(request.remote_addr or '').is_loopback
    except ValueError:
        return False


@app.route('/healthz')
def healthz():
    if not _is_loopback_request():
        return '', 404
    return jsonify({'status': 'ok'})


@app.route('/readyz')
def readyz():
    if not _is_loopback_request():
        return '', 404
    try:
        db = get_db()
        result = db.execute('PRAGMA quick_check(1)').fetchone()
        version_row = db.execute(
            'SELECT MAX(version) FROM schema_migrations'
        ).fetchone()
        metrics = database_metrics(app.config['DATABASE'])
        if (
            not result
            or result[0] != 'ok'
            or version_row[0] != SCHEMA_VERSION
            or metrics['free_bytes'] < _READINESS_MIN_FREE_BYTES
        ):
            raise sqlite3.DatabaseError('database readiness check failed')
        db.execute('BEGIN IMMEDIATE')
        db.rollback()
    except (sqlite3.Error, OSError):
        return jsonify({'status': 'unavailable'}), 503
    return jsonify({
        'status': 'ok',
        'schema_version': SCHEMA_VERSION,
        **metrics,
    })


def get_initial_admin_credentials():
    admin_user = os.environ.get('ANYTLS_ADMIN_USER', 'admin').strip() or 'admin'
    env_password = os.environ.get('ANYTLS_ADMIN_PASS')
    if env_password:
        return admin_user, env_password, ''

    password_file = Path(
        os.environ.get('ANYTLS_ADMIN_PASSWORD_FILE')
        or Path(app.config['DATABASE']).with_name('.initial_admin_password')
    )
    app.config['INITIAL_ADMIN_PASSWORD_FILE'] = str(password_file)
    try:
        if password_file.exists():
            password = password_file.read_text(encoding='utf-8').strip()
            if password:
                return admin_user, password, str(password_file)

        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        password = _read_or_create_private_file(
            password_file,
            lambda: ''.join(secrets.choice(alphabet) for _ in range(18)),
            trailing_newline=True,
        )
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
    if not items or len(items) > MAX_TRAFFIC_BATCH_ITEMS:
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
            session_version INTEGER NOT NULL DEFAULT 1,
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

    apply_schema_migrations(db)
    prune_traffic_logs(db)
    checkpoint_database(db)

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


class _SubscriptionResponseError(OSError):
    """A definitive HTTP response that must not trigger IP failover."""


_SUBSCRIPTION_READ_CHUNK = 64 * 1024
MAX_SYNC_ACCOUNTS = 64
MAX_CHECK_NODES = 320
MAX_NODES_PER_SUBSCRIPTION = 2000
_BULK_OPERATION_LOCK = threading.Lock()
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
    if parsed.scheme == 'http' and not _env_flag('ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS'):
        raise ValueError('默认只允许 HTTPS 上游订阅')

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
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
            remaining = _set_subscription_socket_deadline(sock, deadline)

            connection = http.client.HTTPConnection(
                parsed.hostname,
                port,
                timeout=remaining,
            )
            connection.sock = sock
            # The socket is already pinned to a policy-validated IP address.
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
                    raise _SubscriptionResponseError(
                        '订阅服务器返回了无 Location 的重定向'
                    )
                return None, urljoin(url, location)
            if not 200 <= response.status < 300:
                raise _SubscriptionResponseError(
                    f'订阅服务器返回 HTTP {response.status}'
                )

            raw = _read_subscription_body(response, sock, deadline)
            return raw, None
        except (ValueError, _SubscriptionResponseError):
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
        attempt_errors = []
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
                else:
                    attempt_errors.append(
                        f'{ua.split("/", 1)[0]}: 响应中未找到可用节点'
                    )
            except ValueError:
                raise
            except Exception as exc:
                attempt_errors.append(f'{ua.split("/", 1)[0]}: {exc}')
                continue
        if not candidates:
            detail = '；'.join(attempt_errors) or '所有 UA 均无法访问'
            raise ValueError(f'拉取订阅失败（{detail}）')
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


def parse_anytls_uri(uri):
    """兼容旧调用"""
    return parse_protocol_uri(uri, 'anytls')


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
    if parsed > SQLITE_INTEGER_MAX:
        raise ValueError(f"{field_name}数值过大")
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
    if parsed > SQLITE_INTEGER_MAX:
        raise ValueError(f"{field_name}数值过大")
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
        user_id = session.get('admin_user_id')
        session_version = session.get('session_version')
        if not isinstance(user_id, int) or not isinstance(session_version, int):
            session.clear()
            return redirect(url_for('login'))
        user = get_db().execute(
            'SELECT username, session_version FROM admin_users WHERE id=?',
            (user_id,),
        ).fetchone()
        if (
            not user
            or user['username'] != session.get('username')
            or user['session_version'] != session_version
        ):
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def single_bulk_operation(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _BULK_OPERATION_LOCK.acquire(blocking=False):
            return jsonify({"error": "已有批量任务正在执行，请稍后重试"}), 409
        try:
            return f(*args, **kwargs)
        finally:
            _BULK_OPERATION_LOCK.release()
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
@rate_limit(
    get_db,
    "login",
    5,
    60,
    methods=["POST"],
    error_message="登录尝试过于频繁，请1分钟后再试",
)
def login():
    if request.method == 'POST':
        try:
            username = validate_text(
                request.form.get('username', ''), '用户名', MAX_NAME_CHARS, required=True
            )
            password = validate_text(
                request.form.get('password', ''), '密码', 128, required=True
            )
        except ValueError:
            audit_event('auth.login', 'failure', reason='invalid_input')
            flash('用户名或密码错误', 'error')
            return render_template('login.html')
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
            session.clear()
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['admin_user_id'] = user['id']
            session['session_version'] = user['session_version']
            audit_event('auth.login', 'success', username=username)
            return redirect(url_for('dashboard'))
        audit_event('auth.login', 'failure', username=username)
        flash('用户名或密码错误', 'error')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    username = session.get('username', '')
    session.clear()
    audit_event('auth.logout', 'success', username=username)
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
    node_health = db.execute('''
        SELECT
            SUM(CASE WHEN is_online = 1 THEN 1 ELSE 0 END) AS online_nodes,
            SUM(CASE WHEN is_online = 0 THEN 1 ELSE 0 END) AS offline_nodes,
            SUM(CASE WHEN is_online NOT IN (0, 1) OR is_online IS NULL THEN 1 ELSE 0 END) AS unknown_nodes
        FROM nodes
    ''').fetchone()
    online_nodes = int(node_health['online_nodes'] or 0)
    offline_nodes = int(node_health['offline_nodes'] or 0)
    unknown_nodes = int(node_health['unknown_nodes'] or 0)
    last_synced_at = max(
        (a['last_synced_at'] for a in accounts if a['last_synced_at']),
        default=None,
    )

    warning_accounts = []
    for a in accounts:
        pct = calc_traffic_percent(a['traffic_used_bytes'] or 0, a['traffic_limit_gb'] or 250)
        if pct >= 80:
            warning_accounts.append({**dict(a), 'usage_pct': pct})
    attention_nodes = db.execute('''
        SELECT id, account_id, name, host, port, is_online, last_checked_at
        FROM nodes
        WHERE is_online != 1 OR is_online IS NULL
        ORDER BY CASE WHEN is_online = 0 THEN 0 ELSE 1 END,
                 last_checked_at DESC,
                 id DESC
        LIMIT 3
    ''').fetchall()

    return render_template('dashboard.html',
        accounts=accounts,
        total_accounts=total_accounts,
        active_accounts=active_accounts,
        total_nodes=total_nodes,
        total_traffic_used=total_traffic_used,
        total_traffic_limit=total_traffic_limit,
        warning_accounts=warning_accounts,
        attention_nodes=attention_nodes,
        attention_total=len(warning_accounts) + offline_nodes + unknown_nodes,
        online_nodes=online_nodes,
        offline_nodes=offline_nodes,
        unknown_nodes=unknown_nodes,
        last_synced_at=last_synced_at,
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
    try:
        name = validate_text(request.form.get('name', ''), '账号名称', MAX_NAME_CHARS)
        subscribe_url = validate_text(
            request.form.get('subscribe_url', ''),
            '订阅内容',
            MAX_SUBSCRIPTION_TEXT_CHARS,
            required=True,
        )
        notes = validate_text(request.form.get('notes', ''), '备注', MAX_NOTES_CHARS)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('accounts_list'))
    traffic_limit = request.form.get('traffic_limit_gb', '250').strip()

    try:
        nodes, traffic_info = parse_subscribe_url(subscribe_url)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('accounts_list'))

    if not nodes:
        flash('未解析到节点', 'error')
        return redirect(url_for('accounts_list'))
    if len(nodes) > MAX_NODES_PER_SUBSCRIPTION:
        flash(f'订阅节点超过安全上限 {MAX_NODES_PER_SUBSCRIPTION}', 'error')
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

    audit_event('account.create', 'success', account_id=account_id, node_count=len(nodes))
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
    try:
        new_name = validate_text(
            request.form.get('name', ''), '名称', MAX_NAME_CHARS, required=True
        )
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('account_detail', account_id=account_id))

    db = get_db()
    db.execute(
        'UPDATE accounts SET name=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (new_name, account_id)
    )
    db.commit()
    audit_event('account.rename', 'success', account_id=account_id)
    flash(f'已重命名为 "{new_name}"', 'success')
    return redirect(url_for('account_detail', account_id=account_id))

@app.route('/accounts/<int:account_id>/edit', methods=['POST'])
@login_required
def account_edit(account_id):
    try:
        subscribe_url = validate_text(
            request.form.get('subscribe_url', ''),
            '订阅内容',
            MAX_SUBSCRIPTION_TEXT_CHARS,
            required=True,
        )
        notes = validate_text(request.form.get('notes', ''), '备注', MAX_NOTES_CHARS)
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('account_detail', account_id=account_id))
    traffic_limit = request.form.get('traffic_limit_gb', '250').strip()
    status = request.form.get('status', 'active')
    if status not in {'active', 'suspended', 'disabled'}:
        flash('账号状态无效', 'error')
        return redirect(url_for('account_detail', account_id=account_id))

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
    audit_event('account.update', 'success', account_id=account_id, status=status)
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
        audit_event('account.delete', 'success', account_id=account_id)
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
        if len(nodes) > MAX_NODES_PER_SUBSCRIPTION:
            raise ValueError(
                f'订阅节点超过安全上限 {MAX_NODES_PER_SUBSCRIPTION}'
            )
    except ValueError as e:
        audit_event('account.sync', 'failure', account_id=account_id, reason='invalid_subscription')
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
    audit_event('account.sync', 'success', account_id=account_id, node_count=len(nodes))
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
        audit_event(
            'node.delete',
            'success',
            node_id=node_id,
            account_id=node['account_id'],
        )
        flash('节点已删除', 'success')
        return redirect(url_for('account_detail', account_id=node['account_id']))
    flash('节点不存在', 'error')
    return redirect(url_for('accounts_list'))

# ─── API 流量上报（豁免 CSRF，供外部脚本调用）──────────────────


def _resolve_traffic_account_id(db, item):
    if 'account_id' in item:
        try:
            account_id = parse_nonnegative_int(item['account_id'], 'account_id')
        except ValueError:
            return None, 'account_id must be a nonnegative integer', 400
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
@rate_limit(get_db, "traffic-report", 60, 60)
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
    if len(data) > MAX_TRAFFIC_BATCH_ITEMS:
        return jsonify({
            "error": f"traffic batch may contain at most {MAX_TRAFFIC_BATCH_ITEMS} items"
        }), 413

    db = get_db()
    prune_traffic_logs(db)
    results = []
    for item in data:
        if not isinstance(item, dict):
            return jsonify({"error": "Invalid traffic item"}), 400
        try:
            bytes_used = parse_nonnegative_int(item.get('bytes_used', 0), 'bytes_used')
        except ValueError:
            return jsonify({"error": "bytes_used must be a nonnegative integer"}), 400

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
@rate_limit(get_db, "traffic-counter", 60, 60)
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
    except ValueError:
        return jsonify({"error": "counter_bytes must be a nonnegative integer"}), 400

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
@rate_limit(get_db, "traffic-set", 60, 60)
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
    except ValueError:
        return jsonify({"error": "total_bytes must be a nonnegative integer"}), 400

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

    try:
        host = validate_text(data['host'], 'host', MAX_HOST_CHARS, required=True)
    except ValueError:
        return jsonify({"error": "host 必须是 1-253 个字符"}), 400
    try:
        port = parse_nonnegative_int(data['port'], 'port')
    except ValueError:
        return jsonify({"error": "port 必须是整数"}), 400
    if not 1 <= port <= 65535:
        return jsonify({"error": "port必须在1-65535之间"}), 400

    result = _check_node_connect(host, port)
    db = get_db()
    db.execute(
        'UPDATE nodes SET is_online=?, last_checked_at=CURRENT_TIMESTAMP, latency_ms=? WHERE host=? AND port=?',
        (1 if result['online'] else 0, result.get('latency', -1), host, port)
    )
    db.commit()
    audit_event(
        'node.check_by_host',
        'success',
        status='online' if result['online'] else 'offline',
    )
    return jsonify(result)

@app.route('/api/nodes/<int:node_id>/check', methods=['POST'])
@login_required
def api_check_node(node_id):
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
        audit_event(
            'node.check',
            'success',
            node_id=node_id,
            account_id=node['account_id'],
            status='online' if result['online'] else 'offline',
        )
        return jsonify(result)
    except Exception:
        audit_event('node.check', 'failure', node_id=node_id, reason='probe_error')
        return jsonify({"status": "error", "msg": "节点检测失败"})

@app.route('/api/accounts/<int:account_id>/check-all', methods=['POST'])
@login_required
@single_bulk_operation
def api_check_all_nodes(account_id):
    db = get_db()
    nodes = [dict(node) for node in db.execute(
        'SELECT * FROM nodes WHERE account_id=? ORDER BY id LIMIT ?',
        (account_id, MAX_CHECK_NODES + 1),
    ).fetchall()]
    if len(nodes) > MAX_CHECK_NODES:
        return jsonify({
            "error": f"节点批量检测上限为 {MAX_CHECK_NODES}，请拆分账号后重试"
        }), 413

    def check(node):
        try:
            return node, _check_node_connect(node['host'], node['port']), None
        except Exception:
            return node, None, "节点检测失败"

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
    audit_event(
        'node.check_all',
        'success',
        account_id=account_id,
        node_count=len(nodes),
    )
    return jsonify({"results": results})


def _bounded_parallel_map(function, items, max_workers=8):
    """Run blocking network work concurrently while keeping DB writes in the caller."""
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as executor:
        return list(executor.map(function, items))

def _check_node_connect(host, port, timeout=8):
    """通过受限、固定 IP 的 TLS CONNECT 检测节点可用性。"""
    return check_node_connect(
        host,
        port,
        timeout,
        _resolve_subscription_addresses,
        allow_private=_env_flag('ANYTLS_ALLOW_PRIVATE_NODE_PROBES'),
    )

@app.route('/api/sync-all', methods=['POST'])
@login_required
@single_bulk_operation
def api_sync_all():
    """一键同步所有账号的订阅"""
    db = get_db()
    accounts = [dict(account) for account in db.execute(
        "SELECT * FROM accounts WHERE status='active' ORDER BY id LIMIT ?",
        (MAX_SYNC_ACCOUNTS + 1,),
    ).fetchall()]
    if len(accounts) > MAX_SYNC_ACCOUNTS:
        return jsonify({
            "error": f"单次同步账号上限为 {MAX_SYNC_ACCOUNTS}，请分批同步"
        }), 413

    def fetch(account):
        try:
            nodes, traffic_info = parse_subscribe_url(account['subscribe_url'])
            if len(nodes) > MAX_NODES_PER_SUBSCRIPTION:
                raise ValueError(
                    f'订阅节点超过安全上限 {MAX_NODES_PER_SUBSCRIPTION}'
                )
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
    audit_event(
        'account.sync_all',
        'success',
        node_count=sum(item.get('nodes', 0) for item in results),
    )
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
        audit_event(
            'auth.password_change',
            'failure',
            username=session.get('username', 'admin'),
            reason='invalid_current_password',
        )
        flash('原密码错误', 'error')
        return redirect(url_for('dashboard'))

    new_hash = hash_password(new_pw)
    db.execute(
        'UPDATE admin_users SET password_hash=?, '
        'session_version=session_version + 1 WHERE id=?',
        (new_hash, user['id']),
    )
    db.commit()
    audit_event('auth.password_change', 'success', username=user['username'])
    password_file = app.config.get('INITIAL_ADMIN_PASSWORD_FILE')
    if password_file:
        try:
            Path(password_file).unlink(missing_ok=True)
        except OSError:
            audit_event(
                'auth.initial_password_file_cleanup',
                'failure',
                reason='permission_denied',
            )
    session.clear()
    flash('密码修改成功，请重新登录；其他设备上的旧会话已失效', 'success')
    return redirect(url_for('login'))

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


@app.route('/sub/<token>')
@csrf.exempt
@rate_limit(get_db, "public-subscribe", 120, 60)
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
    sub_name = account['name'] or 'subscription'
    if rules:
        sub_name = _apply_rename(sub_name, rules)
    header_sub_name = sanitize_header_value(sub_name, 'subscription')

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
    audit_event('account.subscription_token.rotate', 'success', account_id=account_id)
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
    try:
        old_text = validate_text(
            request.form.get('old_text', ''),
            '原名称',
            MAX_RENAME_TEXT_CHARS,
            required=True,
        )
        new_text = validate_text(
            request.form.get('new_text', ''),
            '新名称',
            MAX_RENAME_TEXT_CHARS,
        )
    except ValueError as e:
        flash(str(e), 'error')
        return redirect(url_for('rename_rules_page'))
    db = get_db()
    rule_id = db.execute(
        'INSERT INTO rename_rules (old_text, new_text) VALUES (?, ?)',
        (old_text, new_text),
    ).lastrowid
    db.commit()
    audit_event('rename_rule.create', 'success', rule_id=rule_id)
    flash(f'规则已添加：{old_text} → {new_text}', 'success')
    return redirect(url_for('rename_rules_page'))


@app.route('/settings/rename-rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def rename_rule_toggle(rule_id):
    db = get_db()
    db.execute('UPDATE rename_rules SET enabled = 1 - enabled WHERE id=?', (rule_id,))
    db.commit()
    audit_event('rename_rule.toggle', 'success', rule_id=rule_id)
    return redirect(url_for('rename_rules_page'))


@app.route('/settings/rename-rules/<int:rule_id>/delete', methods=['POST'])
@login_required
def rename_rule_delete(rule_id):
    db = get_db()
    db.execute('DELETE FROM rename_rules WHERE id=?', (rule_id,))
    db.commit()
    audit_event('rename_rule.delete', 'success', rule_id=rule_id)
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


def create_app():
    """Initialize persistent state explicitly and return the Flask application."""
    init_db()
    return app

if __name__ == '__main__':
    create_app()
    host, port, debug = _development_server_options()
    print(f"\n  AnyTLS Panel running at http://{host}:{port}")
    if app.config.get('INITIAL_ADMIN_PASSWORD_FILE'):
        print(f"  Initial admin user: admin")
        print(f"  Initial password file: {app.config['INITIAL_ADMIN_PASSWORD_FILE']}\n")
    app.run(host=host, port=port, debug=debug)
