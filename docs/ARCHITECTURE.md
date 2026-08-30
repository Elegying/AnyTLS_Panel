# 架构说明

本文帮助维护者理解 AnyTLS Panel 的组件、数据流和安全边界。它描述当前实现，不是未来路线图。

## 系统组成

```text
浏览器 / 订阅客户端 / 节点采集器
                 │ HTTPS :443
                 ▼
              Caddy
                 │ HTTP 127.0.0.1:8866
                 ▼
         Gunicorn + Flask 应用
                 │
                 ▼
          SQLite 数据与密钥
```

- Caddy 负责公开 HTTPS、证书自动续签和 HTTP 跳转；
- Gunicorn 只监听回环地址，运行在低权限 `anytls-panel` 用户下；
- Flask 提供服务端渲染页面、管理 JSON 接口、流量 API 和公开订阅；
- SQLite 使用 WAL，保存管理员、账号、节点、流量明细、采集器状态、限流状态和迁移版本；
- systemd 管理面板、Caddy 恢复关系和每分钟健康检查。

## 代码模块

| 文件 | 主要职责 |
| --- | --- |
| `app.py` | 应用配置、页面/API 路由、订阅拉取、业务逻辑和审计事件 |
| `db_migrations.py` | 版本化、可重复执行的 SQLite 迁移 |
| `database_maintenance.py` | 流量明细保留策略和数据库维护指标 |
| `protocol_codecs.py` | 协议 URI 解析、Clash 映射和兼容字段保留 |
| `node_probe.py` | 解析目标、阻止私网地址并执行受限 TCP/TLS 探测 |
| `input_limits.py` | 环境变量、文本和数值边界检查 |
| `security_utils.py` | 密码哈希、旧哈希兼容验证和安全升级 |
| `sqlite_rate_limit.py` | 跨进程、跨重启的固定窗口限流 |
| `traffic_token.py` | 从主 Token 派生账号级 HMAC Token |
| `deploy.sh` | 预检、暂存、安装、迁移、HTTPS、验证、备份和回滚 |
| `traffic_collector.sh` | 节点侧 iptables 端口计数和幂等上报 |

`templates/` 保存 Jinja 页面，`static/` 保存统一设计令牌、响应式样式和本地图标资源。生产安装只复制 `release-files.txt` 白名单中的文件，防止数据库、密钥或开发文件被意外打包。

## 主要数据流

### 导入和同步订阅

1. 管理员提交订阅地址或内容；
2. 应用验证长度、格式和协议；
3. HTTPS 订阅先解析 DNS，并拒绝私网、回环、保留和链路本地地址；
4. 连接固定到已经验证的 IP，每次重定向重新校验；
5. 所有 User-Agent 尝试、重定向和读取共享绝对期限，正文也有大小上限；
6. 解析成功后，在短事务中替换该账号节点；空结果或请求失败保留旧节点。

### 流量采集

1. 节点采集器读取自己创建的 iptables 规则累计字节数；
2. 使用稳定 `collector_id` 和账号级 Token 调用 `/api/traffic/counter`；
3. 服务端在 `BEGIN IMMEDIATE` 事务中比较上次原始值；
4. 只把差额写入账号累计量，首次样本只建立基线；
5. 计数器回绕或重置时，从新值继续累计。

### 公开订阅

1. 管理员为账号生成随机分享 Token；
2. `/sub/<token>` 只读取上一次成功同步到本地的数据；
3. 按 User-Agent 返回 Clash YAML 或通用 Base64；
4. 停用账号、删除账号或轮换 Token 会立即使旧 URL 失效。

## 安全边界

- `root` 只用于安装、系统配置和代码更新；Web 请求由低权限用户处理；
- 代码和虚拟环境由 root 所有，服务用户只有 `data/` 写权限；
- 浏览器管理面使用 Session、CSRF 和 CSP；流量 API 不使用浏览器 Session；
- 主 Token 留在面板服务器，账号级 Token 才能发给节点；
- 健康端点只允许回环访问；公开反向代理不应暴露它们；
- 订阅 URL、节点密码、分享 Token 和 API Token 都属于敏感数据；审计日志不记录完整值；
- 网络例外开关会改变信任边界，默认全部关闭。

## 部署与回滚

部署分为两个阶段：

1. **停服前**：拉取固定引用、按白名单暂存文件、下载并验证锁定依赖、复制现有数据库并完成迁移冒烟测试；
2. **切换阶段**：短暂停止服务，保存旧代码和数据库状态，安装新文件、迁移真实数据库、写入 systemd/Caddy 配置并进行本机和 HTTPS 验收。

任一步失败都会尝试恢复旧代码、数据库和服务状态。成功部署保留最近两份带 SHA-256 校验的 LKG 快照。

## 质量门禁

Pull Request 针对 Python 3.12 和 3.13 运行：

- 单元测试和分支覆盖率门槛；
- Python 编译和关键静态检查；
- Bandit 与依赖漏洞审计；
- CodeQL 扩展安全查询，并按周重新扫描主分支；
- Shell 语法与 ShellCheck；
- Ubuntu 24.04 上的真实 systemd、数据库迁移、Caddy 和 LKG 集成测试。

正式标签只能从 `main` 当前提交创建，并且该提交必须已有成功的 push CI。Release 产物包含可复现源码归档、SHA-256 和 Sigstore bundle。

## 当前取舍

- 单机 SQLite 降低了部署和恢复复杂度，但不面向多机高可用；
- 服务端渲染减少了前端构建链和供应链依赖；
- 进程内批量任务锁适合当前单 Worker 部署，不是分布式任务队列；
- iptables 采集器简单可审计，但不能解决 IPv6、共享端口或用户级计量。

改变上述假设时，应同步更新代码、测试、部署脚本、配置参考和本文。
