#!/bin/bash
# AnyTLS Panel 快速启动脚本
set -e

cd "$(dirname "$0")"

# 安装依赖
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q -r requirements.txt

# 启动
PORT=${PORT:-8866}
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   AnyTLS 管理面板                    ║"
echo "  ║   http://0.0.0.0:${PORT}               ║"
echo "  ║   默认账号: admin / admin123         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

exec gunicorn -w 2 -b 0.0.0.0:${PORT} --timeout 60 app:app
