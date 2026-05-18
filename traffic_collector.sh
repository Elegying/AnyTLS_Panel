#!/bin/bash
# AnyTLS 流量采集脚本 - 部署在各节点上
# 定期运行（如 crontab 每5分钟）将流量数据上报到面板
#
# 用法:
#   1. 修改下方配置
#   2. chmod +x traffic_collector.sh
#   3. crontab -e 添加: */5 * * * * /path/to/traffic_collector.sh
#
# 方式一: 通过 iptables 统计 (推荐)
# 方式二: 通过 ss/进程统计连接数
# 方式三: 读取 anytls-go 的日志统计

# ─── 配置 ─────────────────────────────
PANEL_URL="http://面板地址:8866"  # 修改为你的面板地址
PASSWORD="your_password_here"       # 当前节点的 anytls 密码

# ─── iptables 方式 ────────────────────
# 需要先添加 iptables 规则（首次运行自动添加）:
# iptables -I INPUT -p tcp --dport <anytls端口> -j ACCEPT
# iptables -I OUTPUT -p tcp --sport <anytls端口> -j ACCEPT

ANYTLS_PORT=443  # 修改为你的 anytls 端口

# 确保 iptables 规则存在
ensure_iptables() {
    if ! iptables -L INPUT -n -v 2>/dev/null | grep -q "dpt:${ANYTLS_PORT}"; then
        iptables -I INPUT -p tcp --dport ${ANYTLS_PORT}
    fi
    if ! iptables -L OUTPUT -n -v 2>/dev/null | grep -q "spt:${ANYTLS_PORT}"; then
        iptables -I OUTPUT -p tcp --sport ${ANYTLS_PORT}
    fi
}

# 获取流量计数
get_traffic_bytes() {
    local in_bytes=$(iptables -L INPUT -n -v -x 2>/dev/null | grep "dpt:${ANYTLS_PORT}" | awk '{print $2}')
    local out_bytes=$(iptables -L OUTPUT -n -v -x 2>/dev/null | grep "spt:${ANYTLS_PORT}" | awk '{print $2}')
    in_bytes=${in_bytes:-0}
    out_bytes=${out_bytes:-0}
    echo $((in_bytes + out_bytes))
}

# 上报流量
report_traffic() {
    local bytes=$1
    curl -s -X POST "${PANEL_URL}/api/traffic/set" \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"${PASSWORD}\", \"total_bytes\": ${bytes}}" \
        > /dev/null 2>&1
}

# 主逻辑
main() {
    ensure_iptables
    local total_bytes=$(get_traffic_bytes)
    report_traffic ${total_bytes}
}

main
