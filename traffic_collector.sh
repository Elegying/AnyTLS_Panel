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
PANEL_URL="${PANEL_URL:-http://面板地址:8866}"  # 修改为你的面板地址
PASSWORD="${PASSWORD:-your_password_here}"       # 当前节点的 anytls 密码
API_TOKEN="${API_TOKEN:-your_traffic_api_token}"  # 面板部署时输出，或读取 .traffic_api_token
TRAFFIC_STATE_FILE="${TRAFFIC_STATE_FILE:-/var/lib/anytls-panel-traffic.state}"

# ─── iptables 方式 ────────────────────
# 首次运行会添加只计数、不改变 ACCEPT/DROP 决策的 iptables 规则。

ANYTLS_PORT=443  # 修改为你的 anytls 端口
INPUT_RULE_COMMENT="anytls-panel-traffic-in-${ANYTLS_PORT}"
OUTPUT_RULE_COMMENT="anytls-panel-traffic-out-${ANYTLS_PORT}"

# 确保 iptables 规则存在
ensure_iptables() {
    if ! iptables -C INPUT -p tcp --dport "${ANYTLS_PORT}" \
        -m comment --comment "${INPUT_RULE_COMMENT}" >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "${ANYTLS_PORT}" \
            -m comment --comment "${INPUT_RULE_COMMENT}"
    fi
    if ! iptables -C OUTPUT -p tcp --sport "${ANYTLS_PORT}" \
        -m comment --comment "${OUTPUT_RULE_COMMENT}" >/dev/null 2>&1; then
        iptables -I OUTPUT -p tcp --sport "${ANYTLS_PORT}" \
            -m comment --comment "${OUTPUT_RULE_COMMENT}"
    fi
}

# 获取流量计数
get_traffic_bytes() {
    local in_bytes
    local out_bytes
    in_bytes=$(iptables -L INPUT -n -v -x 2>/dev/null | \
        awk -v marker="${INPUT_RULE_COMMENT}" 'index($0, marker) {sum += $2} END {print sum + 0}')
    out_bytes=$(iptables -L OUTPUT -n -v -x 2>/dev/null | \
        awk -v marker="${OUTPUT_RULE_COMMENT}" 'index($0, marker) {sum += $2} END {print sum + 0}')
    in_bytes=${in_bytes:-0}
    out_bytes=${out_bytes:-0}
    echo $((in_bytes + out_bytes))
}

# 把易重置的 iptables 原始计数转换为持久化的单调累计值。
calculate_cumulative_total() {
    local current_bytes=$1
    local previous_bytes=0
    local cumulative_bytes=0
    if [[ -r "${TRAFFIC_STATE_FILE}" ]]; then
        read -r previous_bytes cumulative_bytes < "${TRAFFIC_STATE_FILE}" || true
    fi
    [[ "${previous_bytes}" =~ ^[0-9]+$ ]] || previous_bytes=0
    [[ "${cumulative_bytes}" =~ ^[0-9]+$ ]] || cumulative_bytes=0

    if (( current_bytes >= previous_bytes )); then
        cumulative_bytes=$((cumulative_bytes + current_bytes - previous_bytes))
    else
        cumulative_bytes=$((cumulative_bytes + current_bytes))
    fi
    printf '%s %s\n' "${current_bytes}" "${cumulative_bytes}"
}

persist_traffic_state() {
    local current_bytes=$1
    local cumulative_bytes=$2
    local state_dir
    local temp_file="${TRAFFIC_STATE_FILE}.tmp.$$"
    state_dir=$(dirname "${TRAFFIC_STATE_FILE}")
    mkdir -p "${state_dir}"
    (umask 077; printf '%s %s\n' "${current_bytes}" "${cumulative_bytes}" > "${temp_file}")
    mv -f "${temp_file}" "${TRAFFIC_STATE_FILE}"
}

# 上报流量
report_traffic() {
    local bytes=$1
    curl -fsS --connect-timeout 10 --max-time 30 -X POST "${PANEL_URL}/api/traffic/set" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -d "{\"password\": \"${PASSWORD}\", \"total_bytes\": ${bytes}}" \
        > /dev/null
}

# 主逻辑
main() {
    ensure_iptables
    local current_bytes
    local cumulative_bytes
    current_bytes=$(get_traffic_bytes)
    read -r current_bytes cumulative_bytes <<< "$(calculate_cumulative_total "${current_bytes}")"
    if report_traffic "${cumulative_bytes}"; then
        persist_traffic_state "${current_bytes}" "${cumulative_bytes}"
    else
        return 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
