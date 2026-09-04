# 快速开始

本指南面向第一次部署 AnyTLS Panel 的用户。完成后，你会得到一个带 HTTPS 的管理面板，并导入第一个订阅账号。

## 1. 准备服务器和域名

请先确认：

- 服务器是 Ubuntu 24.04 LTS；
- 你能使用 `root` 登录服务器；
- 域名 A 记录已经指向服务器 IPv4 地址；如果配置了 AAAA 记录，它也必须正确指向这台服务器；
- 云安全组和防火墙允许公网访问 TCP 80、443；
- 服务器能访问 GitHub、Python 包索引和 Caddy 官方软件源。

可以在自己的电脑上检查域名解析：

```bash
dig +short panel.example.com A
dig +short panel.example.com AAAA
```

把 `panel.example.com` 换成你的真实域名。如果还看到旧 IP，请等待 DNS 生效后再部署。

## 2. 下载固定版本的部署脚本

在面板服务器上执行：

```bash
curl -fL \
  https://raw.githubusercontent.com/Elegying/AnyTLS_Panel/v1.4.3/deploy.sh \
  -o /tmp/anytls-panel-deploy.sh
```

建议先查看脚本，再运行：

```bash
less /tmp/anytls-panel-deploy.sh
bash /tmp/anytls-panel-deploy.sh
```

部署过程中需要输入：

1. 管理员用户名；
2. 管理员密码，并再次确认；
3. 面板域名，只填写域名，不要带 `https://` 或路径。

脚本会自动安装运行依赖和 Caddy，创建低权限服务账号，初始化数据库，配置 HTTPS 和健康检查。它会在切换线上服务前完成依赖与数据库副本验证。

## 3. 验证部署

脚本显示成功后，打开：

```text
https://panel.example.com/login
```

如果页面打不开，在服务器检查：

```bash
systemctl is-active anytls-panel caddy
systemctl status anytls-panel caddy --no-pager
journalctl -u anytls-panel -n 50 --no-pager
journalctl -u caddy -n 50 --no-pager
```

正常情况下，前两个服务都应显示 `active`。更多检查项见[运维手册的部署后验证](OPERATIONS.md#部署后验证)。

## 4. 导入第一个订阅

登录后：

1. 打开左侧「账号」；
2. 点击右上角「导入订阅」；
3. 填写账号名称；名称留空时会使用第一个节点名称；
4. 粘贴 HTTPS 订阅地址、Clash YAML、Base64 内容或多行协议链接；
5. 按需填写流量上限和备注；
6. 提交后进入账号详情，确认节点数量和订阅信息。

支持的常见链接包括 `anytls://`、`trojan://`、`vmess://`、`vless://`、`hysteria2://`、`tuic://` 和 `ss://`。

默认禁止 HTTP 和内网订阅，这是安全保护，不是故障。只有在隔离网络且完全信任订阅源时，才参考[配置参考](CONFIGURATION.md#网络边界例外)显式放开。

## 5. 登记用户服务并分发订阅

- 在「监控」中点击单个检测或批量检测，查看在线状态和延迟；
- 打开「用户服务」，登记用户微信号、服务开始日、真实到期日和当前专线账号；
- 把该用户自己的订阅链接发给对方，不要多人共用账号级分享链接；
- 续费时使用“续期”保留历史；流量或有效期需要调整时可迁移专线，用户链接保持不变；
- 仪表盘会显示未来 30 天的续费待办，联系用户后点击“标记已提醒”；
- 在「重命名规则」中批量替换节点名称中的固定文字；
- 分享链接相当于访问凭据，只发给可信对象；怀疑泄露时立即重新生成。

专线账号的“到期日”始终表示真实到期日。系统只取这个日期的日号计算月度流量重置：例如账号到期日是 `2027-04-24`，每月就在 24 日开始新的流量周期。若日号是 29、30 或 31，而当月没有该日期，则按当月最后一天处理。

## 6. 做好上线后的三件事

1. 登录后立即确认管理员密码只由授权人员掌握；
2. 按[运维手册](OPERATIONS.md#更新)建立加密异机备份，并进行恢复演练；
3. 订阅本仓库 Release 或定期查看[更新记录](../CHANGELOG.md)，在测试后升级正式版本。

下一步可阅读[常见问题](FAQ.md)或[完整运维手册](OPERATIONS.md)。
