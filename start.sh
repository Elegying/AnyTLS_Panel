#!/usr/bin/env bash
# AnyTLS Panel 本地开发启动脚本。生产环境请使用 deploy.sh。
set -Eeuo pipefail

cd "$(dirname "$0")"

VENV_DIR="${VENV_DIR:-.venv}"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "正在创建本地虚拟环境：$VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install -q --require-hashes -r requirements.txt

PORT=${PORT:-8866}
HOST=${HOST:-127.0.0.1}
echo ""
echo "  AnyTLS Panel"
echo "  本地地址：http://${HOST}:${PORT}"
echo "  默认用户：admin"
echo "  首次启动密码：查看数据库旁的 .initial_admin_password 文件"
echo "  提示：此脚本仅供本地开发，不要直接暴露到公网。"
echo ""

exec "$VENV_DIR/bin/gunicorn" --workers 1 --threads 4 --no-control-socket \
    --bind "${HOST}:${PORT}" --timeout 120 'app:create_app()'
