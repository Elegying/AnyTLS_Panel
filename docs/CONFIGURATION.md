# 配置参考

AnyTLS Panel 使用环境变量覆盖默认配置。生产环境由 `deploy.sh` 校验并写入 systemd；修改生产配置后应重新运行同一版本的部署脚本，不建议手工编辑生成的 unit 文件。

## 基本规则

- 布尔值只接受 `0` 或 `1`；
- 路径必须使用绝对路径；
- 密码和 Token 不要写进 Git、Shell 历史或公开日志；
- 现有数据库更新时，`ANYTLS_ADMIN_USER` 和 `ANYTLS_ADMIN_PASS` 不会覆盖已有管理员；
- 自定义密钥文件仅允许放在受保护的 `/etc/anytls-panel/<文件名>` 中，且路径不得经过符号链接。

## 部署与服务

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ANYTLS_PANEL_DOMAIN` | 无 | 必填的公网域名，不带协议或路径 |
| `ANYTLS_PANEL_DIR` | `/opt/anytls-panel` | 安装目录，只允许独立的 `/opt/<名称>` 或 `/srv/<名称>` |
| `ANYTLS_PANEL_PORT` | `8866` | Gunicorn 回环监听端口 |
| `ANYTLS_SERVICE_NAME` | `anytls-panel` | systemd 服务名称，也是健康检查和备份目录前缀 |
| `ANYTLS_SERVICE_USER` | `anytls-panel` | 低权限运行用户，不能是 `root` |
| `ANYTLS_BIND_HOST` | `127.0.0.1` | 生产 HTTPS 部署必须保持回环地址 |
| `ANYTLS_REPO_URL` | 官方 GitHub 仓库 | 部署脚本拉取代码的 Git 仓库 |
| `ANYTLS_REPO_REF` | `v1.4.2` | 要部署的正式标签或分支；生产环境建议使用不可变标签 |
| `ANYTLS_REPO_SUBDIR` | 空 | 仓库中的项目子目录，常规部署不需要设置 |
| `ANYTLS_ADMIN_USER` | 交互输入 | 首次无人值守安装时的管理员用户名 |
| `ANYTLS_ADMIN_PASS` | 交互输入或安全随机值 | 首次无人值守安装时的 8–128 字符密码 |
| `ANYTLS_SHOW_SECRETS` | `0` | 设为 `1` 时允许部署输出新生成的敏感值，只用于受控终端 |

无人值守首次安装示例：

```bash
ANYTLS_ADMIN_USER="admin" \
ANYTLS_ADMIN_PASS="请替换为强随机密码" \
ANYTLS_PANEL_DOMAIN="panel.example.com" \
bash deploy.sh
```

在自动化平台中，应从 Secret 管理器注入密码，不要把真实值提交到脚本或仓库。

## 应用安全与资源边界

| 变量 | 默认值 | 合法范围或影响 |
| --- | --- | --- |
| `ANYTLS_SESSION_COOKIE_SECURE` | `1` | 生产环境必须为 `1`，确保 Cookie 只通过 HTTPS 发送 |
| `ANYTLS_TRUST_PROXY` | `1` | 生产环境通过 Caddy 获取客户端协议和地址时启用 |
| `ANYTLS_MAX_REQUEST_BYTES` | `4194304` | 请求体上限，允许 65536–16777216 字节 |
| `ANYTLS_TRAFFIC_LOG_RETENTION_DAYS` | `90` | 流量明细保留天数，允许 1–3650；累计总量不会因清理下降 |
| `ANYTLS_DATABASE` | `<安装目录>/data/anytls.db` | SQLite 数据库文件；不能是空值或目录 |
| `ANYTLS_SECRET_KEY_FILE` | `<数据目录>/.secret_key` | Flask 会话密钥文件 |
| `ANYTLS_TRAFFIC_API_TOKEN_FILE` | `<数据目录>/.traffic_api_token` | 流量主 Token 文件 |
| `ANYTLS_ADMIN_PASSWORD_FILE` | `<数据目录>/.initial_admin_password` | 首次密码引导文件，首次改密后自动删除默认位置中的文件 |
| `ANYTLS_TRAFFIC_API_TOKEN` | 自动生成 | 首次安装时显式提供主 Token；已有 Token 不会被覆盖 |
| `ANYTLS_BACKUP_ROOT` | `/var/backups/<服务名>/daily` | `backup.sh` 的本机灾难恢复备份目录，必须位于 `/var/backups` 下 |
| `ANYTLS_BACKUP_RETENTION_COUNT` | `14` | 自动保留的每日备份份数，允许 2–365 |

## 网络边界例外

以下开关默认关闭，因为它们会扩大 SSRF 或明文传输风险。

| 变量 | 默认值 | 何时才应启用 |
| --- | --- | --- |
| `ANYTLS_ALLOW_HTTP_SUBSCRIPTIONS` | `0` | 仅当可信订阅源无法升级到 HTTPS，并且链路处于受控网络 |
| `ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS` | `0` | 仅当面板必须访问可信内网订阅源，且普通用户不能提交任意地址 |
| `ANYTLS_ALLOW_PRIVATE_NODE_PROBES` | `0` | 仅在隔离网络中需要检测内网节点时 |

三个开关互相独立。例如，允许内网订阅并不会自动允许 HTTP。公网面板通常不应启用任何例外。

```bash
ANYTLS_PANEL_DOMAIN="panel.example.com" \
ANYTLS_ALLOW_PRIVATE_SUBSCRIPTIONS=1 \
bash deploy.sh
```

## 本地开发

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | 本地服务监听地址 |
| `PORT` | `8866` | 本地服务端口 |
| `DEBUG` | `0` | Flask 调试模式；启用时只允许绑定回环地址 |

这些变量面向 `start.sh` 或直接运行 `app.py`。它们不替代生产部署配置。

## 节点流量采集器

`traffic_collector.sh` 在节点服务器运行，不在面板服务器运行。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PANEL_URL` | 无 | 必填的面板 HTTPS 根地址，例如 `https://panel.example.com`；仅回环测试允许 HTTP |
| `ACCOUNT_ID` | 空 | 推荐填写的面板账号 ID |
| `API_TOKEN` | 无 | 必填；推荐使用与 `ACCOUNT_ID` 对应的账号级 Token |
| `PASSWORD` | 无 | 仅供主 Token 兼容定位账号；不推荐新部署使用 |
| `ANYTLS_PORT` | `443` | 当前节点上由该账号独占的 AnyTLS TCP 端口 |
| `COLLECTOR_ID` | 自动持久化 | 采集实例唯一标识，8–128 个安全字符 |
| `COLLECTOR_ID_FILE` | `/var/lib/anytls-panel-traffic.id` | 跨重启保存采集器 ID 的 root 私有文件 |
| `COLLECTOR_LOCK_FILE` | `/run/anytls-panel-traffic.lock` | 防止定时任务和手工执行并发的锁文件 |

最小配置：

```bash
PANEL_URL="https://panel.example.com" \
ACCOUNT_ID="1" \
API_TOKEN="账号级 Token" \
ANYTLS_PORT="443" \
bash traffic_collector.sh
```

采集器基于 iptables，只统计 IPv4 端口总流量。一个采集实例要求一个账号独占一个端口；共享端口、IPv6 或需要按用户计量时不能使用这个脚本。

## 卸载确认

`uninstall.sh` 必须使用 `--yes`，也可设置 `ANYTLS_UNINSTALL_CONFIRM=yes`。保留数据库和项目目录时使用：

```bash
bash /opt/anytls-panel/uninstall.sh --yes --keep-data
```

卸载是破坏性操作。执行前请先按[运维手册](OPERATIONS.md#更新)备份并验证数据库。
