# AnyTLS Panel 运维手册

这份手册面向生产服务器部署、更新、验证和卸载。安装命令默认以 `root` 身份执行；应用进程由部署脚本创建的 `anytls-panel` 专用用户运行。

## 支持环境

- Python 3.10+
- 带 systemd 的 Linux
- `apt-get`、`dnf` 或 `yum` 包管理器
- systemd

部署脚本会先校验 `python3` 版本和 venv/pip 可用性，不满足要求时会在修改系统前失败退出。旧版发行版即使包管理器受支持，也可能因默认 Python 版本过低而不适用。

## 部署

在线部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/main/deploy.sh)
```

克隆后部署：

```bash
git clone https://github.com/Elegying/AnyTLS_Panel.git
cd AnyTLS_Panel
bash deploy.sh
```

部署指定正式版本（推荐生产更新使用）：

```bash
ANYTLS_REPO_REF="v1.0.0" \
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/main/deploy.sh)
```

自定义端口、服务名、目录和管理员账号：

```bash
ANYTLS_PANEL_DIR="/opt/anytls-panel" \
ANYTLS_SERVICE_NAME="anytls-panel" \
ANYTLS_PANEL_PORT="8866" \
ANYTLS_ADMIN_USER="admin" \
ANYTLS_ADMIN_PASS="change-this-password" \
bash deploy.sh
```

首次安装时脚本会初始化管理员账号；如果数据库已存在，会保留原有账号。
未通过 `ANYTLS_ADMIN_PASS` 指定密码时，随机初始密码会保存到面板目录的 `.initial_admin_password`，文件仅 root 可读。部署输出默认隐藏密码和流量 API token；如确需打印敏感值，可临时设置 `ANYTLS_SHOW_SECRETS=1`。

## 生产 HTTPS

不要把管理面板的明文 HTTP 端口直接暴露到公网。推荐让 Caddy、Nginx 或其他 TLS 反向代理监听公网 443，Gunicorn 只监听本机：

```bash
ANYTLS_BIND_HOST="127.0.0.1" \
ANYTLS_SESSION_COOKIE_SECURE="1" \
ANYTLS_TRUST_PROXY="1" \
bash deploy.sh
```

- `ANYTLS_SESSION_COOKIE_SECURE=1` 使浏览器只通过 HTTPS 发送 Session Cookie。
- `ANYTLS_TRUST_PROXY=1` 只适用于面板前方恰好有一层受信任反向代理；直接暴露面板时保持为 `0`。
- 反向代理应覆盖 `X-Forwarded-For`、`X-Forwarded-Proto` 和 `Host`，并将请求转发到 `127.0.0.1:8866`。
- 域名、证书和公网 ACL 属于站点环境信息，部署脚本不会臆测或自动修改。

示例 Caddy 站点片段：

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8866
}
```

HTTP(S) 订阅默认禁止访问内网、回环、链路本地和保留地址。确需拉取可信内网订阅时，可在隔离环境中设置 `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1` 后重新部署；不要在可导入不可信订阅的面板上开启。

## 部署后验证

```bash
systemctl is-active anytls-panel
journalctl -u anytls-panel -n 50 --no-pager
curl -I http://127.0.0.1:8866/login
```

配置 HTTPS 后，还需要从独立客户端验证域名、证书、登录和订阅同步，并确认响应包含 HSTS、安全 Cookie 等安全头。`systemctl active` 只能证明进程存活，不能替代真实业务验收。

## 更新

更新前创建数据库和密钥备份：

```bash
backup_dir="/root/anytls-panel-backup-$(date +%Y%m%d-%H%M%S)"
install -d -m 700 "$backup_dir"
cp -a /opt/anytls-panel/.secret_key /opt/anytls-panel/.traffic_api_token "$backup_dir/"
/opt/anytls-panel/venv/bin/python - \
  /opt/anytls-panel/anytls.db "$backup_dir/anytls.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as backup:
    source.backup(backup)
    result = backup.execute('PRAGMA quick_check').fetchone()[0]
if result != 'ok':
    raise SystemExit(f'database quick_check failed: {result}')
print('database quick_check: ok')
PY
```

重新执行部署脚本即可更新应用文件和依赖，并保留现有数据库：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/main/deploy.sh)
```

如果使用自定义目录或服务名，更新时需要继续传入相同环境变量。

回滚时重新部署上一个已验证标签，再检查数据库完整性、服务日志、登录和订阅输出：

```bash
ANYTLS_REPO_REF="上一个版本标签" \
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/main/deploy.sh)
```

## 卸载

卸载服务和面板目录：

```bash
bash /opt/anytls-panel/uninstall.sh --yes
```

只禁用服务，保留数据库和项目目录：

```bash
bash /opt/anytls-panel/uninstall.sh --yes --keep-data
```

自定义服务名或目录时：

```bash
ANYTLS_PANEL_DIR="/opt/anytls-panel" \
ANYTLS_SERVICE_NAME="anytls-panel" \
bash /opt/anytls-panel/uninstall.sh --yes
```

## 发布前检查

```bash
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -q
python3 -m py_compile app.py
flake8 app.py security_utils.py tests --select=E9,F63,F7,F82
bash -n deploy.sh start.sh traffic_collector.sh uninstall.sh
python3 -m pip_audit -r requirements.txt
```

GitHub Actions 会在 push 和 pull request 时自动运行这些检查。

## 常见排障

- 登录页打不开：检查 `systemctl status anytls-panel` 和端口防火墙。
- 管理员密码不对：确认首次初始化时传入的 `ANYTLS_ADMIN_PASS`，已有数据库不会被覆盖。
- 在线部署失败：确认服务器可以访问 GitHub，或改用克隆部署。
- 订阅导入失败：先确认订阅内容是否是 Clash YAML、Base64 或支持的单链接格式。
- 内网订阅被拒绝：这是默认 SSRF 防护；仅在订阅源完全可信且网络隔离时启用 `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1`。
- HTTPS 下反复跳回登录：确认反向代理发送 `X-Forwarded-Proto: https`，且 `ANYTLS_TRUST_PROXY=1`、`ANYTLS_SESSION_COOKIE_SECURE=1` 配套启用。
