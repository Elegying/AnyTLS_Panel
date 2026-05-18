#!/bin/bash
# AnyTLS 管理面板 - 一键部署脚本
# 用法: bash deploy.sh [端口号]
set -e

PANEL_DIR="/opt/anytls-panel"
PORT="${1:-8866}"
SERVICE_NAME="anytls-panel"

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   AnyTLS 节点统一管理面板 - 一键部署      ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo "❌ 未找到 python3，正在安装..."
    apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip
fi

# 创建目录
echo "📁 创建项目目录: ${PANEL_DIR}"
mkdir -p "${PANEL_DIR}"

# 如果是本目录部署
if [ -f "$(dirname "$0")/app.py" ]; then
    echo "📋 复制项目文件..."
    cp "$(dirname "$0")/app.py" "${PANEL_DIR}/"
    cp "$(dirname "$0")/requirements.txt" "${PANEL_DIR}/"
    mkdir -p "${PANEL_DIR}/templates"
    cp "$(dirname "$0")/templates/"*.html "${PANEL_DIR}/templates/"
    mkdir -p "${PANEL_DIR}/static"
fi

cd "${PANEL_DIR}"

# 创建虚拟环境
if [ ! -d "venv" ]; then
    echo "🐍 创建 Python 虚拟环境..."
    python3 -m venv venv
fi

# 安装依赖
echo "📦 安装依赖..."
source venv/bin/activate
pip install -q -r requirements.txt

# 创建 systemd 服务
echo "⚙️  配置系统服务..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AnyTLS Panel - 节点统一管理面板
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_DIR}/venv/bin/gunicorn -w 2 -b 0.0.0.0:${PORT} --timeout 60 app:app
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" --now
sleep 2

# 检查状态
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    # 获取本机 IP
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    PUBLIC_IP=$(curl -s -m 5 ifconfig.me 2>/dev/null || echo "未知")

    echo ""
    echo "✅ 部署成功！"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  访问地址: http://${LOCAL_IP}:${PORT}"
    if [ "${PUBLIC_IP}" != "未知" ]; then
        echo "  公网地址: http://${PUBLIC_IP}:${PORT}"
    fi
    echo "  默认账号: Elegy"
    echo "  默认密码: J.199326"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "常用命令:"
    echo "  systemctl status ${SERVICE_NAME}   # 查看状态"
    echo "  systemctl restart ${SERVICE_NAME}  # 重启服务"
    echo "  journalctl -u ${SERVICE_NAME} -f   # 查看日志"
    echo ""
else
    echo "❌ 启动失败，请查看日志:"
    echo "  journalctl -u ${SERVICE_NAME} -n 20"
    exit 1
fi
