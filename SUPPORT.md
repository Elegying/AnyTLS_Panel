# 支持说明

本项目由开源维护者按可用时间提供社区支持，不包含商业 SLA、代运维或紧急响应承诺。

## 正式支持范围

- Ubuntu 24.04 LTS；
- Python 3.12 及当前 CI 覆盖的 Python 3.13；
- systemd、Caddy 和 SQLite 的标准单机部署；
- README 列出的订阅格式和协议；
- 最新正式 Release 的安装、更新、回滚和卸载流程。

以下场景欢迎讨论，但目前不作生产兼容承诺：

- Docker、Kubernetes、NAS 应用商店或面板托管环境；
- Debian、Ubuntu 22.04、RHEL 系、Alpine、BSD 或 Windows；
- 多机高可用、外部数据库和分布式任务队列；
- 第三方反向代理替代 Caddy；
- IPv6 或共享端口的节点侧流量计量；
- 修改过的私有分支、来源不明的一键脚本和非官方安装包。

## 提问前

1. 阅读[快速开始](docs/QUICKSTART.md)、[常见问题](docs/FAQ.md)和[运维手册](docs/OPERATIONS.md)；
2. 确认问题在最新正式 Release 中仍可复现；
3. 收集系统版本、项目版本、部署方式和最小复现步骤；
4. 删除日志中的域名、IP、用户名、密码、Token、订阅 URL 和节点凭据；
5. 选择正确的 Issue 模板。

建议附上这些脱敏输出：

```bash
lsb_release -ds
python3 --version
systemctl is-active anytls-panel caddy
systemctl status anytls-panel --no-pager
journalctl -u anytls-panel -n 100 --no-pager
```

不要上传数据库、`.secret_key`、`.traffic_api_token`、`.initial_admin_password`、Caddy 私钥或完整环境文件。

## 使用哪个渠道

- 可复现故障：使用 Bug 报告模板；
- 新功能和兼容性建议：使用功能请求模板；
- 文档小错误：可以直接提交 Pull Request；
- 安全漏洞：不要使用公开 Issue，按[安全策略](SECURITY.md)私下报告。

维护者可以关闭缺少必要信息、超出支持范围、重复或包含敏感数据的 Issue。
