# AnyTLS Panel 运维手册

这份手册面向生产服务器部署、更新、验证和卸载。安装命令默认以 `root` 身份执行；应用进程由部署脚本创建的 `anytls-panel` 专用用户运行。

第一次使用请先阅读[快速开始](QUICKSTART.md)；查找环境变量请看[配置参考](CONFIGURATION.md)；返回全部文档见[文档中心](README.md)。涉及删除、回滚或手工恢复数据库的命令，应先在测试环境演练并确认备份可用。

## 支持环境

- Ubuntu 24.04 LTS（当前唯一经过端到端验证的生产目标）
- Python 3.12+
- systemd 与 `apt-get`
- 已解析到服务器的公网域名
- 公网 TCP 80/443 已在云安全组和主机防火墙中放行

部署脚本会先校验系统版本、`python3`、venv/pip 和基础工具，不满足要求时会在切换应用前失败退出。Debian、Ubuntu 22.04、RHEL 系发行版及非 systemd 环境目前都不在正式支持范围内。

Python 生产依赖由 `requirements.in` 声明，并锁定到带 SHA-256 哈希的 `requirements.txt`。部署在停服前下载、校验并试装全部依赖，切换阶段不再访问 PyPI。

## 部署

在线部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/v1.4.3/deploy.sh)
```

克隆后部署：

```bash
git clone --depth 1 --branch v1.4.3 https://github.com/Elegying/AnyTLS_Panel.git
cd AnyTLS_Panel
bash deploy.sh
```

部署指定正式版本（推荐生产更新使用）：

```bash
ANYTLS_REPO_REF="v1.4.3" \
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/v1.4.3/deploy.sh)
```

首次交互部署会要求输入管理员用户名、两次输入密码以及面板域名。密码输入不会回显。自定义端口、服务名和目录时仍会显示这些提示：

```bash
ANYTLS_PANEL_DIR="/opt/anytls-panel" \
ANYTLS_SERVICE_NAME="anytls-panel" \
ANYTLS_PANEL_PORT="8866" \
bash deploy.sh
```

无人值守部署必须显式提供所需输入：

```bash
ANYTLS_ADMIN_USER="admin" \
ANYTLS_ADMIN_PASS="replace-with-a-strong-password" \
ANYTLS_PANEL_DOMAIN="panel.example.com" \
bash deploy.sh
```

首次安装时脚本会初始化管理员账号；如果数据库已存在，会保留原有账号，不会用环境变量覆盖。首次密码会暂存到面板 `data/.initial_admin_password`，文件仅 root 可读，并在管理员首次修改密码后自动删除。若通过 `ANYTLS_ADMIN_PASSWORD_FILE` 把文件放在受保护的 `/etc/anytls-panel/`，systemd 沙箱不允许应用删除它；首次改密后应由 root 手工删除该自定义文件。部署输出默认隐藏密码和流量 API token；如确需打印敏感值，可临时设置 `ANYTLS_SHOW_SECRETS=1`。

部署目录必须是 `/opt/<专用名称>` 或 `/srv/<专用名称>`，且父目录由 root 所有并不可组/全局写。脚本会拒绝符号链接路径以及没有 AnyTLS 安装标记的非空目录；卸载时也会在停止服务前验证同一标记。代码和每次重建的 venv 由 root 所有且服务只读，数据库、WAL 和运行密钥位于服务可写的 `data/` 子目录。旧版根目录状态会在停服后通过 SQLite backup/安全复制迁入 `data/`。

自定义 `ANYTLS_TRAFFIC_API_TOKEN_FILE`、`ANYTLS_ADMIN_PASSWORD_FILE` 或 `ANYTLS_SECRET_KEY_FILE` 时，只允许 `/etc/anytls-panel/<文件名>`；父目录必须由 root 所有、不可组/全局写且整条目标路径不得经过符号链接。更新时继续传入同一路径。

## 生产 HTTPS

部署脚本自动完成以下工作：

1. 校验输入的是公网 DNS 域名并确认其当前可解析。
2. 从 Caddy 官方 Cloudsmith 稳定仓库安装并验证签名和最低版本，将 Gunicorn 保持在 `127.0.0.1:<面板端口>`。
3. 写入 `/etc/caddy/anytls-panel.d/<服务名>.caddy`，并安全地导入现有 Caddyfile。
4. 使用 Caddy 默认的公开 ACME 签发方签发证书，自动将 HTTP 跳转至 HTTPS。
5. 等待 `https://<域名>/login` 通过真实证书校验后才报告部署成功。
6. 为面板和 Caddy 配置异常自动拉起，并安装每分钟运行一次的本机健康检查 timer；连续三次失败才触发恢复，两次恢复至少间隔五分钟，降低短暂抖动造成的重启风暴。
7. 安装每日灾难恢复备份 timer；默认在每天 03:15 后的随机 30 分钟内执行，并保留最近 14 份备份。

生成的站点配置等价于：

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8866
}
```

Caddy 常驻服务会在证书到期前自动续签，不使用 cron，也不是自签证书。健康检查会在证书剩余有效期不足 21 天或无法读取证书时写入 `certificate_expiring` 警告。部署脚本强制启用 Secure Cookie 与可信代理处理，并拒绝把 Gunicorn 改为公网监听。若端口 80/443 已被其他服务占用、域名尚未生效或云安全组阻断 ACME 验证，部署会显示 Caddy 日志并失败退出。

订阅默认只允许 HTTPS，并禁止访问内网、回环、链路本地和保留地址。确需明文 HTTP 时设置 `ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS=1`；确需拉取可信内网订阅时设置 `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1`。节点检测默认也只连接公网地址，可信隔离网络可通过 `ANYTLS_ALLOW_PRIVATE_NODE_PROBES=1` 放开。三个开关互相独立，取值只能为 `0` 或 `1`；不要在可接收不可信输入的面板上开启例外。

面板默认拒绝超过 4 MiB 的请求体，可用 `ANYTLS_MAX_REQUEST_BYTES` 在 64 KiB 到 16 MiB 之间调整。流量明细默认保留 90 天，可用 `ANYTLS_TRAFFIC_LOG_RETENTION_DAYS` 设置为 1–3650 天；后台按小时检查并清理过期明细，但账号累计流量不会被扣减。修改这些值后需重新运行部署脚本，使 systemd 环境与应用配置保持一致。

## 主机与 SSH 加固

面板应用已经使用独立低权限账号，但操作系统仍需要单独加固。生产服务器至少应满足：

- 日常登录使用具备 `sudo` 权限的非 root 账号；确认该入口可用后设置 `PermitRootLogin no`；
- 设置 `PasswordAuthentication no` 和 `KbdInteractiveAuthentication no`，只接受独立 SSH 密钥；
- 主机防火墙默认拒绝入站，只放行 SSH、TCP 80/443 和确实使用的业务端口；使用 HTTP/3 时还需放行 UDP 443；
- 启用 Fail2ban、自动安全更新和日志轮转；定期检查被封禁来源、待重启服务和剩余磁盘；
- 自动部署使用独立账号、独立密钥和受限 `sudoers` 命令，不复用维护者日常私钥，也不给部署账号通用 root shell。

修改 SSH 前必须保持一个已登录会话，并在另一个终端验证非 root 密钥登录和 `sudo -n`。只有验证成功后才能关闭 root 登录；否则可能永久失去远程访问。主机还承载邮件、数据库等其他服务时，应先盘点监听端口，不能照抄只允许 22/80/443 的规则。

## 节点流量采集

面板 `data/.traffic_api_token` 是具有全部账号流量写权限的主 Token，不能分发到节点。为账号 ID `1` 生成账号级 Token：

```bash
sudo -u anytls-panel /opt/anytls-panel/venv/bin/python \
  /opt/anytls-panel/traffic_token.py 1
```

该命令可从任意工作目录执行，且不会启动面板或迁移数据库。自定义主 Token 文件时追加 `--token-file /etc/anytls-panel/<文件名>`。

在节点配置 `ACCOUNT_ID=1`、上述账号级 `API_TOKEN`、`ANYTLS_PORT` 和 HTTPS 面板地址。`COLLECTOR_ID_FILE` 必须持久化且每个节点/采集实例唯一；首次样本只建立基线，不回算历史。

脚本依赖 util-linux 的 `flock`，默认通过 `/run/anytls-panel-traffic.lock` 保证单实例执行；可用 `COLLECTOR_LOCK_FILE` 自定义。自定义 ID/锁文件必须是绝对路径，父目录需预先创建，且整条目录链由 root 所有、不可组/全局写；禁止放在 `/tmp` 或普通用户目录。当前 iptables 计数仅覆盖 IPv4，并且按端口而不是 AnyTLS 用户区分。每个被采集的 IPv4 端口必须只对应一个面板账号，且同一端口只能运行一个 collector。双栈/纯 IPv6或共享端口需要用户级指标，不能使用 `traffic_collector.sh` 做账号计费。

## 私密导入用户服务

用户服务包含客户标识和服务期，属于业务敏感数据，不应提交到 Git、Issue、Release 或普通日志。批量导入前，先在面板中建立并同步所有上游专线账号；JSON 中的账号名称必须与面板完全一致。

导入文件是一个数组，每条记录使用以下字段：

```json
[
  {
    "wechat_id": "示例用户",
    "account": "上游账号名称",
    "relationship": "自用",
    "started_on": "2026-09-01",
    "expires_on": "2027-08-31",
    "notes": ""
  }
]
```

将本地文件以受限权限放入服务器数据目录，再用面板服务账号执行导入：

```bash
install -o anytls-panel -g anytls-panel -m 600 \
  /安全路径/customer-services.json \
  /opt/anytls-panel/data/customer-services-import.json

runuser -u anytls-panel -- /opt/anytls-panel/venv/bin/python \
  /opt/anytls-panel/import_customer_services.py \
  --database /opt/anytls-panel/data/anytls.db \
  --source /opt/anytls-panel/data/customer-services-import.json

rm -f /opt/anytls-panel/data/customer-services-import.json
```

工具会先验证全部账号名称和日期，再开启写事务；有任何未知账号或非法记录时整批失败，不会只导入一半。重复导入会按“专线账号 + 微信号 + 开始日期”更新原记录并保留用户 Token，因此可以安全复跑。导入完成后登录「用户服务」核对总数、到期日、专线分配和覆盖警告，并确认临时文件已删除。

## 部署后验证

```bash
systemctl is-active anytls-panel
journalctl -u caddy -n 50 --no-pager
journalctl -u anytls-panel -n 50 --no-pager
curl -I https://panel.example.com/login
curl --fail http://127.0.0.1:8866/healthz
curl --fail http://127.0.0.1:8866/readyz
```

`/healthz` 只证明应用进程响应；`/readyz` 还检查数据库完整性、迁移版本、可写锁、数据库/WAL 体积和剩余磁盘空间。两个端点仅允许回环访问。部署脚本会从服务器本机验证证书与登录页；仍建议从独立客户端验证域名、证书、登录和订阅同步，并确认响应包含 HSTS、安全 Cookie 和 CSP 等安全头。`systemctl active` 只能证明进程存活，不能替代真实业务验收。

## 更新

更新前创建数据库和密钥备份：

```bash
backup_dir="/root/anytls-panel-backup-$(date +%Y%m%d-%H%M%S)"
staging_dir="$(mktemp -d /var/tmp/anytls-panel-backup.XXXXXX)"
trap 'rm -rf -- "$staging_dir"' EXIT
chown anytls-panel:anytls-panel "$staging_dir"
chmod 700 "$staging_dir"
install -d -m 700 "$backup_dir"
cp -a /opt/anytls-panel/data/.secret_key \
  /opt/anytls-panel/data/.traffic_api_token "$backup_dir/"
runuser -u anytls-panel -- /opt/anytls-panel/venv/bin/python - \
  /opt/anytls-panel/data/anytls.db "$staging_dir/anytls.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as backup:
    source.backup(backup)
    result = backup.execute('PRAGMA quick_check').fetchone()[0]
if result != 'ok':
    raise SystemExit(f'database quick_check failed: {result}')
print('database quick_check: ok')
PY
install -m 600 "$staging_dir/anytls.db" "$backup_dir/anytls.db"
rm -rf -- "$staging_dir"
trap - EXIT
```

这份备份包含管理员哈希、订阅凭据、公开订阅 token、面板密钥和流量主 Token，不能以明文长期留在同一台服务器。生产环境应使用组织批准的备份系统把整个目录加密后复制到异机/对象存储，并至少保留一份不可变版本；例如已配置 `age` 公钥时可执行：

```bash
tar -C "$(dirname "$backup_dir")" -czf - "$(basename "$backup_dir")" \
  | age -r 'age1替换为备份公钥' \
  > "${backup_dir}.tar.gz.age"
sha256sum "${backup_dir}.tar.gz.age" > "${backup_dir}.tar.gz.age.sha256"
```

加密文件和校验文件上传异机后，应删除本机长期明文副本。至少每季度在隔离的 Ubuntu 24.04 主机执行一次恢复演练：校验 SHA-256、解密归档、对数据库运行 `PRAGMA quick_check`，将数据库和三个密钥文件恢复到全新安装的 `data/`，校正为服务用户所有且权限 `600`，启动服务后验证 `/readyz`、管理员登录、订阅输出和账号累计流量。演练记录应包含备份时间、恢复耗时、数据库版本和验证结果。

从 `v1.3.0` 开始，部署脚本还会启用每日本机备份。它使用 SQLite 在线备份 API 获取一致快照，把数据库和运行密钥写入 root 专用压缩包，生成外层 SHA-256，并在创建后立即执行归档与数据库完整性校验：

```bash
# 立即创建一份备份
sudo /opt/anytls-panel/backup.sh

# 查看和验证备份
sudo /opt/anytls-panel/backup.sh --list
sudo /opt/anytls-panel/backup.sh --verify latest

# 检查定时任务及最近日志
systemctl list-timers anytls-panel-backup.timer --all
journalctl -u anytls-panel-backup.service -n 30 --no-pager
```

默认目录是 `/var/backups/anytls-panel/daily/`，默认保留 14 份。这里仍属于同机明文备份，只解决误操作、数据库损坏和快速恢复，不替代加密异机备份。至少要定期把其中一份校验通过的归档加密复制到另一台主机或对象存储。

重新执行部署脚本即可更新应用文件和依赖，并保留现有数据库。脚本先完成源码暂存、带哈希依赖下载和现有数据库副本迁移测试，再停止服务进行短切换；切换后任一步失败都会自动恢复旧代码、数据库、systemd 和 Caddy 配置。成功更新还会在 `/var/backups/<服务名>/` 保留最近两份带 SHA-256 校验的上一版本快照：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/v1.4.3/deploy.sh)
```

更新时会再次询问面板域名，已有数据库不会再次询问或覆盖管理员凭据。自动化更新可设置 `ANYTLS_PANEL_DOMAIN`。如果使用自定义目录、服务名或 `/etc/anytls-panel/` 下的密钥文件，更新时需要继续传入相同环境变量。

部署成功后可检查保活状态：

```bash
systemctl is-active anytls-panel caddy anytls-panel-healthcheck.timer anytls-panel-backup.timer
systemctl list-timers anytls-panel-healthcheck.timer anytls-panel-backup.timer --all
journalctl -u anytls-panel-healthcheck.service -n 30 --no-pager
journalctl -t anytls-panel-healthcheck -n 30 --no-pager
```

列出可用 LKG 快照并回滚到最新一份：

```bash
/opt/anytls-panel/deploy.sh --list-backups
/opt/anytls-panel/deploy.sh --rollback latest
```

也可将 `latest` 换成列表中的完整 `backup-...` 标识。脚本会先校验快照哈希，并在回滚前为当前状态再建安全快照；之后恢复代码、数据库、Caddy 和 systemd unit 的 active/enabled 状态。回滚完成后检查数据库、服务日志、登录和订阅输出。若没有 LKG 快照，再使用已验证的旧标签重新部署。

## 卸载

卸载服务和面板目录：

```bash
bash /opt/anytls-panel/uninstall.sh --yes
```

卸载 systemd、健康检查和 Caddy 站点配置，但保留数据库和项目目录：

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
brew install python@3.12 shellcheck actionlint
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -q
.venv/bin/python -m coverage run --branch -m unittest discover -s tests -q
.venv/bin/python -m coverage report --include='app.py,database_maintenance.py,db_migrations.py,input_limits.py,node_probe.py,protocol_codecs.py,security_utils.py,sqlite_rate_limit.py,traffic_token.py' --fail-under=80
.venv/bin/python -m py_compile app.py database_maintenance.py db_migrations.py \
  input_limits.py node_probe.py protocol_codecs.py security_utils.py \
  sqlite_rate_limit.py traffic_token.py
.venv/bin/python -m flake8 app.py database_maintenance.py db_migrations.py \
  input_limits.py node_probe.py protocol_codecs.py \
  security_utils.py sqlite_rate_limit.py traffic_token.py tests \
  --select=E9,F63,F7,F82,F401,F811
bash -n backup.sh deploy.sh start.sh traffic_collector.sh uninstall.sh tests/ubuntu24_integration.sh
shellcheck backup.sh deploy.sh start.sh traffic_collector.sh uninstall.sh tests/ubuntu24_integration.sh
actionlint
.venv/bin/python -m bandit -q -ll -r app.py database_maintenance.py \
  db_migrations.py input_limits.py node_probe.py protocol_codecs.py \
  security_utils.py sqlite_rate_limit.py traffic_token.py
.venv/bin/python -m pip_audit -r requirements.txt
```

以上命令固定使用带哈希的开发依赖锁，适用于 macOS 本地质量门禁。GitHub Actions 会在 push 和 pull request 时使用 Python 3.12、3.13 运行同等检查，并在干净的 Ubuntu 24.04 runner 上完成旧数据库迁移、真实 systemd 服务、Caddy 配置与 LKG 校验集成测试。

## 维护者自动发布与部署

标签发布工作流先验证标签正好指向通过 CI 的 `main`，再构建带 SHA-256 和 Sigstore bundle 的源码包。配置生产变量后，工作流会通过独立 SSH 账号部署这个不可变标签，检查公网登录页、HSTS 与 CSP，全部成功后才把草稿 Release 发布为正式版本。

仓库变量：

- `PROD_HOST`：生产服务器地址；
- `PROD_USER`：受限部署账号，建议使用 `anytls-deploy`；
- `PROD_URL`：生产 HTTPS 根地址。

仓库 Secrets：

- `PROD_SSH_PRIVATE_KEY`：仅供 Actions 使用的独立 Ed25519 私钥；
- `PROD_SSH_KNOWN_HOSTS`：经过人工核对指纹的固定服务器公钥记录。

服务器上的部署账号只应获准免密执行一个 root-owned 包装器，例如 `/usr/local/sbin/deploy-anytls-panel`。包装器必须校验 `vX.Y.Z` 标签格式、使用部署锁、固定官方仓库和域名，并在返回成功前验证 systemd 服务、本机 `/readyz` 与 HTTPS。不要把普通管理员私钥或不受限制的 `NOPASSWD: ALL` 放入 GitHub Secrets。

## 常见排障

- 登录页打不开：检查 `systemctl status anytls-panel caddy`、`journalctl -u caddy`、域名解析以及云安全组/防火墙的 TCP 80/443。
- 管理员密码不对：确认首次部署时输入或通过 `ANYTLS_ADMIN_PASS` 提供的密码；已有数据库不会被覆盖。
- 在线部署失败：确认服务器可以访问 GitHub，或改用克隆部署。
- ACME 证书签发失败：确认 A/AAAA 记录指向当前服务器，Caddy 可以占用 80/443，且这两个端口能从公网访问。
- 订阅导入失败：先确认订阅内容是否是 Clash YAML、Base64 或支持的单链接格式。
- 内网订阅被拒绝：这是默认 SSRF 防护；仅在订阅源完全可信且网络隔离时启用 `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1`。
- HTTP 订阅被拒绝：改用 HTTPS；只有无法升级的可信源才启用 `ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS=1`。
- 内网节点检测被拒绝：这是节点探测边界；仅在可信隔离网络启用 `ANYTLS_ALLOW_PRIVATE_NODE_PROBES=1`。
- HTTPS 下反复跳回登录：确认当前 Caddy 站点仍反向代理到面板端口，且 systemd 服务中的 `ANYTLS_TRUST_PROXY=1`、`ANYTLS_SESSION_COOKIE_SECURE=1` 未被手工覆盖。
