# AnyTLS Panel 运维手册

这份手册面向生产服务器部署、更新、验证和卸载。所有命令默认以 `root` 身份执行。

## 支持环境

- Ubuntu 20.04 / 22.04 / 24.04 / 26.04
- Debian 11 / 12
- Python 3.8+
- systemd

部署脚本当前面向 Ubuntu/Debian 的 `apt-get` 环境。

## 部署

在线部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/SSR_Panel/main/anytls-panel/deploy.sh)
```

克隆后部署：

```bash
git clone https://github.com/Elegying/SSR_Panel.git
cd SSR_Panel/anytls-panel
bash deploy.sh
```

自定义端口、服务名、目录和管理员账号：

```bash
ANYTLS_PANEL_DIR="/opt/anytls-panel" \
ANYTLS_SERVICE_NAME="anytls-panel" \
ANYTLS_PANEL_PORT="8866" \
ANYTLS_REPO_SUBDIR="anytls-panel" \
ANYTLS_ADMIN_USER="admin" \
ANYTLS_ADMIN_PASS="change-this-password" \
bash deploy.sh
```

首次安装时脚本会初始化管理员账号；如果数据库已存在，会保留原有账号。

## 部署后验证

```bash
systemctl is-active anytls-panel
journalctl -u anytls-panel -n 50 --no-pager
curl -I http://127.0.0.1:8866/login
```

## 更新

重新执行部署脚本即可更新应用文件和依赖，并保留现有数据库：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Elegying/SSR_Panel/main/anytls-panel/deploy.sh)
```

如果使用自定义目录或服务名，更新时需要继续传入相同环境变量。

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
bash -n deploy.sh start.sh traffic_collector.sh uninstall.sh
```

GitHub Actions 会在 push 和 pull request 时自动运行这些检查。

## 常见排障

- 登录页打不开：检查 `systemctl status anytls-panel` 和端口防火墙。
- 管理员密码不对：确认首次初始化时传入的 `ANYTLS_ADMIN_PASS`，已有数据库不会被覆盖。
- 在线部署失败：确认服务器可以访问 GitHub，或改用克隆部署。
- 订阅导入失败：先确认订阅内容是否是 Clash YAML、Base64 或支持的单链接格式。
