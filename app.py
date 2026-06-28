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
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, g
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from security_utils import hash_password, verify_password

app = Flask(__name__)
app.config['DATABASE'] = os.environ.get(
    'ANYTLS_DATABASE',
    os.path.join(os.path.dirname(__file__), 'anytls.db'),
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24小时
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token 1小时有效

# CSRF 保护
csrf = CSRFProtect(app)

# 登录速率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

# 固定 secret_key，存文件持久化，多 worker 共享
_sk_file = os.path.join(os.path.dirname(__file__), '.secret_key')
if os.path.exists(_sk_file):
    with open(_sk_file, encoding='utf-8') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_sk_file, 'w', encoding='utf-8') as f:
        f.write(app.secret_key)

# ─── 数据库 ──────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
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
        password = ''.join(secrets.choice(alphabet) for _ in range(18))
        password_file.parent.mkdir(parents=True, exist_ok=True)
        password_file.write_text(password + '\n', encoding='utf-8')
        try:
            password_file.chmod(0o600)
        except OSError:
            pass
        app.config['INITIAL_ADMIN_PASSWORD_FILE'] = str(password_file)
        return admin_user, password, str(password_file)
    except OSError:
        password = secrets.token_urlsafe(18)
        return admin_user, password, ''


def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.executescript('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subscribe_url TEXT NOT NULL,
            traffic_limit_gb REAL DEFAULT 250,
            traffic_used_bytes INTEGER DEFAULT 0,
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
            'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
            (admin_user, pw_hash)
        )
        db.commit()

    # 迁移：添加 sub_token 列
    try:
        db.execute('ALTER TABLE accounts ADD COLUMN sub_token TEXT DEFAULT ""')
        db.commit()
    except sqlite3.OperationalError:
        pass  # 列已存在

    db.close()

# ─── 订阅解析 ──────────────────────────────────────────────

def parse_subscribe_url(url):
    """解析订阅链接，返回节点列表。支持:
    1. anytls://password@host:port?params#name  (单链接)
    2. base64 编码的多行订阅
    3. HTTP(S) URL 返回的订阅内容 (Clash YAML / 纯文本)
    """
    import yaml
    nodes = []

    # 情况1：直接是 anytls:// 链接
    if url.strip().startswith('anytls://'):
        for line in url.strip().splitlines():
            line = line.strip()
            if line:
                node = parse_anytls_uri(line)
                if node:
                    nodes.append(node)
        return nodes, {}

    # 情况2：尝试作为 HTTP URL 拉取（用 Shadowrocket UA 以获取全部协议节点）
    content = url.strip()
    traffic_info = {}
    if content.startswith('http://') or content.startswith('https://'):
        fetched = False
        for ua in [
            'Shadowrocket/2209 CFNetwork/1410.1 Darwin/22.6.0',
            'ClashForAndroid/2.5.12',
        ]:
            try:
                import urllib.request
                req = urllib.request.Request(content, headers={'User-Agent': ua})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    raw = resp.read()
                    text = raw.decode('utf-8', errors='ignore').strip()
                    # 尝试 base64 解码（Shadowrocket 格式返回 base64）
                    try:
                        decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                        if '://' in decoded:
                            text = decoded
                    except Exception:
                        pass
                    # 解析 STATUS 行（流量信息）
                    for line in text.splitlines():
                        if line.startswith('STATUS='):
                            traffic_info = _parse_status_line(line)
                            break
                    content = text
                    fetched = True
                    break
            except Exception:
                continue
        if not fetched:
            raise ValueError("拉取订阅失败（所有 UA 均无法访问）")

    # 尝试作为 Clash YAML 解析（最高优先级）
    clash_nodes = _parse_clash_yaml(content)
    if clash_nodes:
        return clash_nodes, traffic_info

    # 尝试 base64 解码后再解析
    try:
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        if '://' in decoded:
            content = decoded
    except Exception:
        pass

    # 再次尝试 Clash YAML（base64 解码后可能是 YAML）
    clash_nodes = _parse_clash_yaml(content)
    if clash_nodes:
        return clash_nodes, traffic_info

    # 按行解析各种协议链接
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # 尝试 base64 解码单行
        try:
            decoded_line = base64.b64decode(line).decode('utf-8', errors='ignore')
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

    if not nodes:
        preview = content[:100].replace('\n', ' ').replace('\r', '')
        raise ValueError(f"订阅中未找到可用节点 (内容前100字符: {preview})")
    return nodes, traffic_info


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

                # 构建统一的 raw_uri
                if ptype in ('anytls', 'anytls1'):
                    uri = f"anytls://{password}@{host}:{port}?security=tls&allowInsecure=0#{name}"
                elif ptype == 'trojan':
                    sni = p.get('sni', host)
                    skip_cert = '1' if p.get('skip-cert-verify') else '0'
                    uri = f"trojan://{password}@{host}:{port}?sni={sni}&allowInsecure={skip_cert}#{name}"
                elif ptype == 'vmess':
                    import base64 as b64
                    vmess_obj = {"v": "2", "ps": name, "add": host, "port": str(port),
                                 "id": password, "aid": str(p.get('alterId', 0)),
                                 "net": p.get('network', 'tcp'), "type": "none",
                                 "host": p.get('ws-opts', {}).get('headers', {}).get('Host', ''),
                                 "path": p.get('ws-opts', {}).get('path', ''),
                                 "tls": "tls" if p.get('tls') else "none"}
                    uri = "vmess://" + b64.b64encode(json.dumps(vmess_obj).encode()).decode()
                elif ptype == 'vless':
                    flow = p.get('flow', '')
                    sni = p.get('sni', host)
                    uri = f"vless://{password}@{host}:{port}?security=tls&sni={sni}&flow={flow}#{name}"
                elif ptype in ('hysteria2', 'hy2', 'hysteria'):
                    auth = password
                    sni = p.get('sni', host)
                    uri = f"hysteria2://{auth}@{host}:{port}?sni={sni}#{name}"
                elif ptype == 'tuic':
                    uri = f"tuic://{password}@{host}:{port}?sni={p.get('sni', host)}#{name}"
                elif ptype == 'shadowsocks':
                    method = p.get('cipher', 'aes-256-gcm')
                    import base64 as b64
                    userinfo = b64.b64encode(f"{method}:{password}".encode()).decode()
                    uri = f"ss://{userinfo}@{host}:{port}#{name}"
                else:
                    # 其他类型也导入，保留原始信息
                    uri = f"{ptype}://{password}@{host}:{port}#{name}"

                nodes.append({
                    'name': str(name),
                    'host': str(host),
                    'port': port,
                    'password': str(password),
                    'raw_uri': uri,
                    'protocol': ptype,
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
                data = json.loads(b64.b64decode(payload).decode())
                return {
                    'name': data.get('ps', data.get('add', 'unknown')),
                    'host': data.get('add', ''),
                    'port': int(data.get('port', 443)),
                    'password': data.get('id', ''),
                    'raw_uri': uri,
                    'protocol': 'vmess',
                }
            except Exception:
                return None

        # ss:// 特殊处理
        if protocol == 'ss':
            try:
                payload = uri.split('://', 1)[1]
                if '#' in payload:
                    payload, frag = payload.rsplit('#', 1)
                else:
                    frag = ''
                if '@' in payload:
                    userinfo, hostport = payload.split('@', 1)
                    import base64 as b64
                    try:
                        userinfo = b64.b64decode(userinfo + '==').decode()
                    except Exception:
                        pass
                    method, password = userinfo.split(':', 1)
                    host, port = hostport.split(':', 1)
                    return {
                        'name': unquote(frag) if frag else f"{host}:{port}",
                        'host': host,
                        'port': int(port),
                        'password': password,
                        'raw_uri': uri,
                        'protocol': 'shadowsocks',
                    }
            except Exception:
                return None

        # 通用格式：scheme://password@host:port/?params#name
        # 也支持 scheme://password@host:port?params#name
        match = re.match(
            r'[a-zA-Z0-9]+://([^@]+)@([^:/?#]+):(\d+)(?:/)?(?:\?([^#]*))?(?:#(.*))?',
            uri
        )
        if not match:
            return None

        password, host, port_str, query_str, frag = match.groups()
        params = parse_qs(query_str or '')
        name = unquote(frag) if frag else f"{host}:{port_str}"

        return {
            'name': name,
            'host': host,
            'port': int(port_str),
            'password': unquote(password),
            'raw_uri': uri,
            'protocol': protocol,
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

    db = get_db()
    cursor = db.execute(
        '''INSERT INTO accounts (name, subscribe_url, traffic_limit_gb, notes, node_count, last_synced_at, traffic_used_bytes)
           VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)''',
        (name, subscribe_url, float(traffic_limit), notes, len(nodes), traffic_info.get('used_bytes', 0))
    )
    account_id = cursor.lastrowid

    # 保存到期时间到 notes（如果没有手动填 notes）
    if traffic_info.get('expire_date') and not notes:
        db.execute('UPDATE accounts SET notes=? WHERE id=?',
                   (f"到期: {traffic_info['expire_date']}", account_id))

    for n in nodes:
        db.execute(
            '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (account_id, n['name'], n['host'], n['port'], n['password'], n.get('raw_uri', ''))
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

    db = get_db()
    db.execute(
        '''UPDATE accounts SET subscribe_url=?, traffic_limit_gb=?, notes=?, status=?,
           updated_at=CURRENT_TIMESTAMP WHERE id=?''',
        (subscribe_url, float(traffic_limit), notes, status, account_id)
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
        db.execute('DELETE FROM nodes WHERE account_id=?', (account_id,))
        db.execute('DELETE FROM accounts WHERE id=?', (account_id,))
        db.execute('DELETE FROM traffic_logs WHERE account_id=?', (account_id,))
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
    except ValueError as e:
        flash(f'同步失败: {e}', 'error')
        return redirect(url_for('account_detail', account_id=account_id))

    # 清除旧节点，重新插入
    db.execute('DELETE FROM nodes WHERE account_id=?', (account_id,))
    for n in nodes:
        db.execute(
            '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (account_id, n['name'], n['host'], n['port'], n['password'], n.get('raw_uri', ''))
        )
    # 更新流量信息（白名单校验字段名，防止SQL注入）
    allowed_fields = {'node_count', 'traffic_used_bytes', 'traffic_limit_gb', 'notes'}
    field_clauses = ['node_count=?', 'last_synced_at=CURRENT_TIMESTAMP', 'updated_at=CURRENT_TIMESTAMP']
    update_params = [len(nodes)]
    if traffic_info.get('used_bytes'):
        field_clauses.append('traffic_used_bytes=?')
        update_params.append(traffic_info['used_bytes'])
    if traffic_info.get('total_gb'):
        field_clauses.append('traffic_limit_gb=?')
        update_params.append(traffic_info['total_gb'])
    if traffic_info.get('expire_date'):
        field_clauses.append('notes=?')
        update_params.append(f"到期: {traffic_info['expire_date']}")
    update_params.append(account_id)
    update_sql = f"UPDATE accounts SET {', '.join(field_clauses)} WHERE id=?"
    db.execute(update_sql, update_params)
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
        SELECT n.host, n.port, n.name, n.is_online, n.last_checked_at,
               n.protocol, n.raw_uri, n.password, n.latency_ms,
               COUNT(DISTINCT n.account_id) as account_count
        FROM nodes n
        GROUP BY n.host, n.port
        ORDER BY n.host, n.port
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

@app.route('/api/traffic/report', methods=['POST'])
@csrf.exempt
def api_report_traffic():
    """上报流量: {"account_id": 1, "bytes_used": 123} 或 {"password": "xxx", ...}"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    if isinstance(data, dict):
        data = [data]

    db = get_db()
    results = []
    for item in data:
        account_id = item.get('account_id')
        password = item.get('password')
        bytes_used = item.get('bytes_used', 0)

        if not account_id and password:
            node = db.execute('SELECT account_id FROM nodes WHERE password=?', (password,)).fetchone()
            if node:
                account_id = node['account_id']

        if not account_id:
            results.append({"status": "error", "msg": "account not found"})
            continue

        account = db.execute('SELECT id, traffic_used_bytes FROM accounts WHERE id=?', (account_id,)).fetchone()
        if not account:
            results.append({"status": "error", "msg": "account not found"})
            continue

        new_total = (account['traffic_used_bytes'] or 0) + bytes_used
        db.execute(
            'UPDATE accounts SET traffic_used_bytes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
            (new_total, account_id)
        )
        db.execute(
            'INSERT INTO traffic_logs (account_id, bytes_used) VALUES (?, ?)',
            (account_id, bytes_used)
        )
        results.append({"account_id": account_id, "status": "ok", "total_bytes": new_total})

    db.commit()
    return jsonify({"results": results})

@app.route('/api/traffic/set', methods=['POST'])
def api_set_traffic():
    """设置流量绝对值: {"account_id": 1, "total_bytes": 999}"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    account_id = data.get('account_id')
    password = data.get('password')
    total_bytes = data.get('total_bytes', 0)

    db = get_db()
    if not account_id and password:
        node = db.execute('SELECT account_id FROM nodes WHERE password=?', (password,)).fetchone()
        if node:
            account_id = node['account_id']

    if not account_id:
        return jsonify({"error": "account not found"}), 404

    db.execute(
        'UPDATE accounts SET traffic_used_bytes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
        (total_bytes, account_id)
    )
    db.commit()
    return jsonify({"status": "ok", "total_bytes": total_bytes})

@app.route('/api/accounts')
@login_required
@csrf.exempt
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
@csrf.exempt
def api_check_by_host():
    """按 host:port 检测节点，并更新所有匹配节点的状态"""
    data = request.get_json(silent=True)
    if not data or not data.get('host') or not data.get('port'):
        return jsonify({"error": "missing host/port"}), 400

    host = data['host']
    port = int(data['port'])

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
@csrf.exempt
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
@csrf.exempt
def api_check_all_nodes(account_id):
    db = get_db()
    nodes = db.execute('SELECT * FROM nodes WHERE account_id=?', (account_id,)).fetchall()
    results = []
    for node in nodes:
        try:
            r = _check_node_connect(node['host'], node['port'])
            db.execute(
                'UPDATE nodes SET is_online=?, last_checked_at=CURRENT_TIMESTAMP WHERE id=?',
                (1 if r['online'] else 0, node['id'])
            )
            results.append({"node_id": node['id'], "name": node['name'], "online": r['online'], "msg": r['msg']})
        except Exception as e:
            results.append({"node_id": node['id'], "name": node['name'], "online": False, "msg": str(e)})
    db.commit()
    return jsonify({"results": results})

def _check_node_connect(host, port, timeout=8):
    """通过 TLS CONNECT 检测节点可用性，返回延迟"""
    import socket
    import ssl
    import time
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.time()
    try:
        sock.connect((host, port))
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
            sock.close()
        except Exception:
            pass

@app.route('/api/sync-all', methods=['POST'])
@login_required
@csrf.exempt
def api_sync_all():
    """一键同步所有账号的订阅"""
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE status='active' ORDER BY id").fetchall()
    results = []
    for account in accounts:
        try:
            nodes, traffic_info = parse_subscribe_url(account['subscribe_url'])
            db.execute('DELETE FROM nodes WHERE account_id=?', (account['id'],))
            for n in nodes:
                db.execute(
                    '''INSERT INTO nodes (account_id, name, host, port, password, raw_uri)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (account['id'], n['name'], n['host'], n['port'], n['password'], n.get('raw_uri', ''))
                )
            # 更新流量信息（白名单校验字段名，防止SQL注入）
            field_clauses = ['node_count=?', 'last_synced_at=CURRENT_TIMESTAMP', 'updated_at=CURRENT_TIMESTAMP']
            update_params = [len(nodes)]
            if traffic_info.get('used_bytes'):
                field_clauses.append('traffic_used_bytes=?')
                update_params.append(traffic_info['used_bytes'])
            if traffic_info.get('total_gb'):
                field_clauses.append('traffic_limit_gb=?')
                update_params.append(traffic_info['total_gb'])
            if traffic_info.get('expire_date'):
                field_clauses.append('notes=?')
                update_params.append(f"到期: {traffic_info['expire_date']}")
            update_params.append(account['id'])
            update_sql = f"UPDATE accounts SET {', '.join(field_clauses)} WHERE id=?"
            db.execute(update_sql, update_params)
            results.append({"id": account['id'], "name": account['name'], "status": "ok", "nodes": len(nodes)})
        except Exception as e:
            results.append({"id": account['id'], "name": account['name'], "status": "error", "msg": str(e)})
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
            link = f"anytls://{n['password']}@{n['host']}:{n['port']}?security=tls&allowInsecure=0#{n['name']}"
            links.append(link)
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
    if len(new_pw) < 6:
        flash('密码至少6个字符', 'error')
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


# ─── 订阅缓存（避免每次请求都拉上游）──────────────────────────
_sub_cache = {}  # {account_id: {"ts": timestamp, "nodes": [...], "traffic_info": {...}}}
_SUB_CACHE_TTL = 300  # 5 分钟


def _fetch_sub_cached(account_id, subscribe_url):
    """带缓存的订阅拉取"""
    now = time.time()
    cached = _sub_cache.get(account_id)
    if cached and now - cached['ts'] < _SUB_CACHE_TTL:
        return cached['nodes'], cached['traffic_info']
    nodes, traffic_info = parse_subscribe_url(subscribe_url)
    _sub_cache[account_id] = {'ts': now, 'nodes': nodes, 'traffic_info': traffic_info}
    return nodes, traffic_info


@app.route('/sub/<token>')
@csrf.exempt
def public_subscribe(token):
    """公开订阅端点：拉取上游订阅（带缓存）→ 应用重命名规则 → 返回转换后的订阅"""
    if not token:
        return 'Invalid token', 404

    db = get_db()
    account = db.execute('SELECT * FROM accounts WHERE sub_token=?', (token,)).fetchone()
    if not account:
        return 'Not found', 404

    rules = db.execute('SELECT old_text, new_text FROM rename_rules WHERE enabled=1 ORDER BY id').fetchall()

    # 从上游拉取（5分钟缓存）
    try:
        nodes, traffic_info = _fetch_sub_cached(account['id'], account['subscribe_url'])
    except Exception as e:
        # 拉取失败时 fallback 到 DB
        db_nodes = db.execute('SELECT * FROM nodes WHERE account_id=? ORDER BY id', (account['id'],)).fetchall()
        nodes = [{'raw_uri': n['raw_uri'], 'name': n['name']} for n in db_nodes]
        traffic_info = {}

    # 构建订阅配置名称（profile-title）
    sub_name = 'SSRVPN.VIP'  # 默认名
    if rules:
        sub_name = _apply_rename(sub_name, rules)

    # 公共响应头：profile-title 设置订阅名 + 流量信息
    resp_headers = {
        'profile-title': f'"store-name={sub_name}"',
        'Content-Disposition': f'attachment; filename="{sub_name}"',
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

    if not rules:
        # 没有重命名规则，直接返回原始订阅
        links = []
        for n in nodes:
            links.append(n.get('raw_uri', ''))
        content = '\n'.join(links)
        resp_headers['Content-Type'] = 'text/plain; charset=utf-8'
        return content, 200, resp_headers

    # 构建转换后的节点链接
    lines = []
    for n in nodes:
        uri = n.get('raw_uri', '')
        if not uri:
            continue
        # anytls:// → trojan://（Shadowrocket 不支持 anytls 协议名）
        if uri.startswith('anytls://'):
            try:
                m = re.match(r'anytls://([^@]+)@([^:/?#]+):(\d+)(?:/)?(?:\?([^#]*))?(?:#(.*))?', uri)
                if m:
                    pw, host, port, q, frag = m.groups()
                    from urllib.parse import parse_qs, urlencode, quote
                    params = parse_qs(q or '')
                    sni = params.get('sni', [host])[0]
                    new_params = urlencode({'sni': sni, 'allowInsecure': '0'})
                    name = quote(unquote(frag), safe='') if frag else ''
                    uri = f'trojan://{pw}@{host}:{port}?{new_params}#{name}'
            except Exception:
                pass
        # 处理 vmess://（base64 JSON，名字在 ps 字段）
        if uri.startswith('vmess://'):
            try:
                payload = uri.split('://', 1)[1]
                data = json.loads(base64.b64decode(payload).decode())
                data['ps'] = _apply_rename(data.get('ps', ''), rules)
                uri = 'vmess://' + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
            except Exception:
                pass
        else:
            # 通用格式：替换 fragment (#name) 中的名字
            if '#' in uri:
                base_part, frag = uri.rsplit('#', 1)
                frag = unquote(frag)
                frag = _apply_rename(frag, rules)
                from urllib.parse import quote
                uri = base_part + '#' + quote(frag, safe='')
            # 也替换 URI 中其他位置出现的匹配文本（如 host 中的域名）
            uri = _apply_rename(uri, rules)
        lines.append(uri)

    # 根据 User-Agent 返回不同格式
    ua = request.headers.get('User-Agent', '')
    content = '\n'.join(lines)

    if 'Clash' in ua or 'clash' in ua:
        # 返回 Clash YAML
        proxies = []
        for line in lines:
            node = None
            for scheme in ('anytls://', 'trojan://', 'vmess://', 'vless://', 'hysteria2://', 'hy2://', 'ss://'):
                if line.startswith(scheme):
                    node = parse_protocol_uri(line, scheme.rstrip(':/'))
                    break
            if not node:
                continue
            p = node['protocol']
            proxy = {'name': node['name'], 'server': node['host'], 'port': node['port']}
            if p in ('anytls', 'anytls1'):
                proxy['type'] = 'trojan'
                proxy['password'] = node['password']
                proxy['sni'] = node['host']
                proxy['skip-cert-verify'] = False
            elif p == 'trojan':
                proxy['type'] = 'trojan'
                proxy['password'] = node['password']
                proxy['sni'] = node['host']
            elif p == 'vmess':
                proxy['type'] = 'vmess'
                proxy['uuid'] = node['password']
                proxy['alterId'] = 0
                proxy['cipher'] = 'auto'
            elif p in ('hysteria2', 'hy2'):
                proxy['type'] = 'hysteria2'
                proxy['password'] = node['password']
                proxy['sni'] = node['host']
            elif p == 'vless':
                proxy['type'] = 'vless'
                proxy['uuid'] = node['password']
                proxy['sni'] = node['host']
            elif p == 'shadowsocks':
                proxy['type'] = 'ss'
                proxy['cipher'] = 'aes-256-gcm'
                proxy['password'] = node['password']
            else:
                proxy['type'] = p
                proxy['password'] = node['password']
            proxies.append(proxy)

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
@csrf.exempt
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

init_db()

if __name__ == '__main__':
    init_db()  # 兼容直接运行
    port = int(os.environ.get('PORT', 8866))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('DEBUG', '0') == '1'
    print(f"\n  AnyTLS Panel running at http://{host}:{port}")
    if app.config.get('INITIAL_ADMIN_PASSWORD_FILE'):
        print(f"  Initial admin user: admin")
        print(f"  Initial password file: {app.config['INITIAL_ADMIN_PASSWORD_FILE']}\n")
    app.run(host=host, port=port, debug=debug)
