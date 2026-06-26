# AnyTLS 节点统一管理面板

[GitHub Actions](https://github.com/Elegying/SSR_Panel/actions)

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
bash <(curl -sL https://raw.githubusercontent.com/Elegying/SSR_Panel/main/anytls-panel/deploy.sh)
```

### 方式二：克隆部署

```bash
git clone https://github.com/Elegying/SSR_Panel.git
cd SSR_Panel/anytls-panel
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

## 🔌 API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/traffic/report` | POST | 上报流量 |
| `/api/traffic/set` | POST | 设置流量绝对值 |
| `/api/accounts` | GET | 获取所有账号 |
| `/api/accounts/<id>/nodes` | GET | 获取账号下所有节点 |
| `/api/check-by-host` | POST | 按地址检测节点 |
| `/api/nodes/<id>/check` | POST | 检测指定节点 |
| `/api/accounts/<id>/check-all` | POST | 批量检测账号节点 |
| `/api/sync-all` | POST | 同步所有账号订阅 |
| `/api/subscribe` | GET | 获取所有节点订阅链接 |

### 流量上报示例

```bash
# 按账号 ID 上报
curl -X POST http://面板地址:8866/api/traffic/report \
  -H "Content-Type: application/json" \
  -d '{"account_id": 1, "bytes_used": 1073741824}'

# 按密码定位账号
curl -X POST http://面板地址:8866/api/traffic/report \
  -H "Content-Type: application/json" \
  -d '{"password": "xxx", "bytes_used": 1073741824}'
```

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

# 修改端口
# 编辑 /etc/systemd/system/anytls-panel.service 中的端口号
# 然后执行: systemctl daemon-reload && systemctl restart anytls-panel
```

## 📁 项目结构

```
anytls-panel/
├── app.py                  # 主程序（Flask 应用）
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

- ✅ CSRF 保护（所有 POST 表单验证 Token）
- ✅ 登录速率限制（5次/分钟，防暴力破解）
- ✅ API 接口豁免 CSRF（供外部脚本调用）
- ✅ Session HttpOnly + SameSite=Lax
- ✅ 密码 SHA256 哈希存储
- ✅ Secret Key 持久化（多 Worker 共享）

## 📋 环境要求

- Python 3.8+
- Linux（推荐 Ubuntu 20.04+）
- 512MB+ 内存

## 📄 开源协议

MIT License

## 🙏 致谢

- [Flask](https://flask.palletsprojects.com/)
- [Gunicorn](https://gunicorn.org/)
- [PyYAML](https://pyyaml.org/)
