# AnyTLS 节点统一管理面板

[GitHub Actions](https://github.com/Elegying/AnyTLS_Panel/actions)

轻量级 Web 面板，通过订阅导入统一管理多个代理节点账号。支持 anytls / trojan / vmess / vless / hysteria2 / tuic / shadowsocks 等多种协议。

## 📚 运维文档

- [生产部署、更新、卸载与排障手册](docs/OPERATIONS.md)
- 每次 push / pull request 会通过 GitHub Actions 自动运行单元测试、编译检查和 shell 语法检查。

## ✨ 功能特性

- 📥 **订阅导入** — 支持 HTTP 订阅地址、Clash YAML、Base64 编码、单链接等多种格式
- 👤 **多账号管理** — 每个订阅对应一个账号，支持重命名、编辑、删除
- 🔄 **一键同步** — 单账号或全部账号一键更新订阅，自动解析流量信息
- 📊 **流量监控** — 自动获取已用流量、总流量、到期时间，进度条可视化
- 📡 **节点检测** — TLS CONNECT 方式检测节点可用性，显示延迟
- 🔗 **节点分享** — 一键复制节点链接
- 🔐 **安全加固** — CSRF 保护、登录速率限制、Session 安全配置
- 🎨 **暗黑主题** — 现代化深色 UI，响应式布局

## 🚀 一键部署

### 方式一：在线部署

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/v1.1.0/deploy.sh)
```

首次部署会依次提示输入面板管理员用户名、隐藏输入并确认密码，以及面板域名。请先把域名的 A/AAAA 记录指向服务器，并在云安全组/防火墙放行 TCP 80 和 443。脚本会从 Caddy 官方稳定仓库安装受支持版本，由 Caddy 自动选择公开 ACME 签发方、启用 HTTP→HTTPS 跳转并自动续签证书。

部署会先在独立暂存目录下载锁定依赖、创建测试环境并完成应用初始化验证，之后才短暂停止线上服务进行切换。切换、数据库迁移、Caddy 或健康检查失败时会自动恢复旧代码、数据库和系统配置。不要直接修改 `requirements.txt`；调整依赖时更新 `requirements.in` 并重新生成带哈希的锁文件。

无人值守部署可预先设置 `ANYTLS_ADMIN_USER`、`ANYTLS_ADMIN_PASS` 和 `ANYTLS_PANEL_DOMAIN`；已有数据库更新时保留原管理员账号，只需输入域名。

正式 Release 同时提供版本化源码归档、SHA-256 和 Sigstore bundle。下载三个同名资产后可验证：

```bash
gh release verify v1.1.0 --repo Elegying/AnyTLS_Panel
gh release verify-asset v1.1.0 AnyTLS_Panel-v1.1.0.tar.gz \
  --repo Elegying/AnyTLS_Panel
sha256sum -c AnyTLS_Panel-v1.1.0.tar.gz.sha256
cosign verify-blob \
  --bundle AnyTLS_Panel-v1.1.0.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/Elegying/AnyTLS_Panel/.github/workflows/release.yml@refs/tags/v1.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  AnyTLS_Panel-v1.1.0.tar.gz
```

### 方式二：克隆部署

```bash
git clone --depth 1 --branch v1.1.0 https://github.com/Elegying/AnyTLS_Panel.git
cd AnyTLS_Panel
bash deploy.sh
```

### 方式三：自定义端口

```bash
bash deploy.sh 9090
```

## 📸 界面预览

| 仪表盘 | 账号管理 | 节点检测 |
|--------|---------|---------|
| 流量总览、一键同步 | 订阅导入、卡片展示 | 延迟检测、状态监控 |

## 📖 使用说明

### 导入订阅

1. 点击「账号管理」→「导入订阅」
2. 粘贴订阅链接（支持以下格式）：
   - HTTP(S) 订阅地址（自动拉取，兼容 Clash / Shadowrocket 格式）
   - `anytls://` / `trojan://` / `vmess://` 等单链接
   - 多行链接（每行一个）
   - Base64 编码的订阅内容
3. 点击导入，自动解析节点和流量信息

### 节点检测

1. 点击「节点检测」导航项
2. 点击「一键检测全部」或单独检测某个节点
3. 显示状态（在线/离线）和延迟（ms）

### 流量同步

- 仪表盘点击「一键同步全部」更新所有账号
- 或进入账号详情点击「同步订阅」更新单个账号

HTTP(S) 订阅默认拒绝回环、内网、链路本地和保留地址，并会逐次校验重定向目标；DNS 解析、所有 User-Agent 尝试、重定向和正文读取共享 10 秒绝对期限，响应上限为 2 MiB。只有确实需要从可信内网订阅源导入时，才应在隔离网络中设置 `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1`。停用账号后，已有公开订阅链接立即失效并返回 404。

## 🔌 API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/traffic/report` | POST | 上报流量 |
| `/api/traffic/counter` | POST | 幂等上报采集器累计计数 |
| `/api/traffic/set` | POST | 单调设置流量绝对值（不会降低已有总量） |
| `/api/accounts` | GET | 获取所有账号 |
| `/api/accounts/<id>/nodes` | GET | 获取账号下所有节点 |
| `/api/check-by-host` | POST | 按地址检测节点 |
| `/api/nodes/<id>/check` | POST | 检测指定节点 |
| `/api/accounts/<id>/check-all` | POST | 批量检测账号节点 |
| `/api/sync-all` | POST | 同步所有账号订阅 |
| `/api/subscribe` | GET | 获取所有节点订阅链接 |

### 流量上报示例

```bash
# 面板管理员使用主 Token 按账号 ID 上报（不要把主 Token 分发到节点）
curl -X POST http://面板地址:8866/api/traffic/report \
  -H "Authorization: Bearer YOUR_TRAFFIC_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": 1, "bytes_used": 1073741824}'

# 主 Token 兼容按密码定位账号
curl -X POST http://面板地址:8866/api/traffic/report \
  -H "Authorization: Bearer YOUR_TRAFFIC_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "xxx", "bytes_used": 1073741824}'
```

流量上报接口使用 Bearer token 鉴权。部署脚本生成的 `data/.traffic_api_token` 是可操作全部账号的主 Token，只应留在面板服务器，不能复制到节点。自定义 `ANYTLS_TRAFFIC_API_TOKEN_FILE` 时只允许使用 `/etc/anytls-panel/<文件名>`，并要求目录由 root 所有且不可组/全局写。

为节点生成只绑定单个账号的采集 Token（将 `1` 替换为账号 ID）：

```bash
sudo -u anytls-panel /opt/anytls-panel/venv/bin/python \
  /opt/anytls-panel/traffic_token.py 1
```

该命令不依赖当前工作目录，也不会启动面板或执行数据库迁移。若部署时把主 Token 文件自定义到 `/etc/anytls-panel/<文件名>`，追加 `--token-file /etc/anytls-panel/<文件名>`。

账号级 Token 必须与 JSON 中同一个 `account_id` 一起使用；它不能按密码定位，也不能修改其他账号。轮换面板主 Token 会同时使所有账号级 Token 失效。

节点上的 `traffic_collector.sh` 使用 `/api/traffic/counter`：每个采集器持久化独立 ID，服务端按原始计数差值幂等入账，网络重试不会重复计费，iptables 计数重置也能继续累计。节点必须配置明确的 `ACCOUNT_ID` 和对应的账号级 Token。仅用密码定位是主 Token 的兼容模式；如果同一密码属于多个账号，接口会返回 409 而不会静默错账。

采集器最小配置示例：

```bash
PANEL_URL="https://panel.example.com" \
ACCOUNT_ID="1" \
API_TOKEN="YOUR_ACCOUNT_SCOPED_TOKEN" \
ANYTLS_PORT="443" \
bash traffic_collector.sh
```

默认采集器 ID 保存在 `/var/lib/anytls-panel-traffic.id`。该文件必须跨更新持久保留，并且每个节点/采集实例使用不同文件；可用 `COLLECTOR_ID_FILE` 自定义。首次接入只登记当前计数为基线，不会把旧版已入账流量重复计算，从下一次采样开始累计差值。

采集脚本依赖 util-linux 的 `flock`，并默认使用 `/run/anytls-panel-traffic.lock` 防止 cron 与手工执行并发造成重复规则或重复计费；可用 `COLLECTOR_LOCK_FILE` 自定义锁文件。自定义 `COLLECTOR_ID_FILE` 或 `COLLECTOR_LOCK_FILE` 必须使用绝对路径，父目录需预先创建，并保证整条目录链由 root 所有且不可组/全局写；不要放在 `/tmp` 或普通用户目录。

当前 iptables 方案只统计 IPv4 的整个 `ANYTLS_PORT`，不能统计 IPv6，也不能区分同端口内的不同 AnyTLS 用户。因此一个采集实例只适用于“一个 IPv4 独占端口对应一个面板账号”，同一端口也只能运行一个 collector。双栈/纯 IPv6或共享端口场景必须改用 AnyTLS/进程提供的用户级指标，不能用此脚本做账号级计费。

首次输入的管理员密码会保存到仅 root 可读的 `data/.initial_admin_password`，用于数据库初始化；部署输出默认隐藏密码和流量 API token。如确需打印敏感值，可临时设置 `ANYTLS_SHOW_SECRETS=1`。

## 🛠️ 管理命令

```bash
# 服务管理
systemctl status anytls-panel    # 查看状态
systemctl restart anytls-panel   # 重启
systemctl stop anytls-panel      # 停止

# 查看日志
journalctl -u anytls-panel -f    # 实时日志
journalctl -u anytls-panel -n 50 # 最近50条

# 修改密码
# 登录后点击左下角「修改密码」

# 修改后端端口（会同步更新 Caddy 反向代理）
ANYTLS_PANEL_DOMAIN="panel.example.com" bash deploy.sh 9090
```

## 📁 项目结构

```
AnyTLS_Panel/
├── app.py                  # 主程序（Flask 应用）
├── security_utils.py       # 密码哈希与兼容校验
├── traffic_token.py        # 账号级流量 Token 生成器
├── templates/              # HTML 模板
│   ├── base.html          # 基础布局
│   ├── login.html         # 登录页
│   ├── dashboard.html     # 仪表盘
│   ├── accounts.html      # 账号管理
│   ├── account_detail.html # 账号详情
│   └── monitor.html       # 节点检测
├── requirements.txt       # Python 依赖
├── deploy.sh              # 一键部署脚本
├── start.sh               # 开发启动脚本
├── anytls-panel.service   # Systemd 服务文件
├── traffic_collector.sh   # 流量采集脚本（部署在节点上）
└── README.md              # 项目说明
```

## 🔒 安全特性

- ✅ 浏览器管理 POST 接口验证 CSRF Token；流量 API 使用独立 Bearer Token
- ✅ SQLite 持久化登录速率限制（5次/分钟，跨进程和重启生效）
- ✅ 流量上报 API 支持账号级 Bearer token，节点不能跨账号写入
- ✅ Session HttpOnly + SameSite=Lax
- ✅ 生产进程使用专用低权限用户和 systemd 沙箱
- ✅ 密码使用带随机盐的 PBKDF2-SHA256，并兼容旧 SHA256 哈希自动升级
- ✅ Secret Key 原子持久化，避免并发启动产生不同会话密钥
- ✅ 订阅拉取拒绝常规内网/回环目标，并限制重定向和响应体大小
- ✅ 订阅连接固定到已验证的公网 IP，阻断 DNS 重绑定到内网地址
- ✅ 严格 CSP、无内联事件处理器、请求 ID 与不记录秘密的结构化审计日志
- ✅ systemd 自动拉起面板与 Caddy；每分钟检查就绪性、HTTPS 与证书剩余有效期，连续三次失败才恢复服务，并用五分钟冷却抑制重启风暴
- ✅ 更新前预构建依赖并验证应用，切换失败自动恢复上一版本和数据库；成功更新保留两份带校验和的 LKG 备份

生产部署会自动把 Gunicorn 绑定到 `127.0.0.1`，并写入独立的 Caddy 站点片段 `/etc/caddy/anytls-panel.d/anytls-panel.caddy`。Caddy 使用默认公开 ACME 签发方签发受信任证书并自动续签；这里不会使用自签证书。部署服务限制为 256 MiB 内存、64 个任务和 4096 个文件描述符；批量同步/检测设有数量上限，且同一时刻只允许一个批处理，避免失控并发耗尽服务资源。

自动化部署示例：

```bash
ANYTLS_ADMIN_USER="admin" \
ANYTLS_ADMIN_PASS="replace-with-a-strong-password" \
ANYTLS_PANEL_DOMAIN="panel.example.com" \
bash deploy.sh
```

若服务器已有 Caddy 配置，脚本只添加一次 `import anytls-panel.d/*.caddy`，并在重启前运行配置校验。完整的 HTTPS、备份、更新和回滚步骤见[运维手册](docs/OPERATIONS.md)。

## 📋 环境要求

- Ubuntu 24.04 LTS（当前唯一经过端到端验证的生产目标）
- Python 3.12+
- systemd 与 `apt-get`
- 可解析到服务器的公网域名，且 TCP 80/443 可从公网访问
- 可访问 Caddy 官方 Cloudsmith 稳定仓库和 Python 包索引
- 512MB+ 内存

## 📄 开源协议

MIT License

## 🙏 致谢

- [Flask](https://flask.palletsprojects.com/)
- [Gunicorn](https://gunicorn.org/)
- [PyYAML](https://pyyaml.org/)
