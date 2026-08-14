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
ACCOUNT_ID="${ACCOUNT_ID:-}"                     # 推荐填写，避免相同密码跨账号歧义
API_TOKEN="${API_TOKEN:-your_account_scoped_token}"  # 使用绑定 ACCOUNT_ID 的账号级 Token
COLLECTOR_ID="${COLLECTOR_ID:-}"
COLLECTOR_ID_FILE="${COLLECTOR_ID_FILE:-/var/lib/anytls-panel-traffic.id}"
COLLECTOR_LOCK_FILE="${COLLECTOR_LOCK_FILE:-/run/anytls-panel-traffic.lock}"

# ─── iptables 方式 ────────────────────
# 首次运行会添加只计数、不改变 ACCEPT/DROP 决策的 iptables 规则。

ANYTLS_PORT="${ANYTLS_PORT:-443}"  # 修改为你的 anytls 端口
# 一个采集实例必须独占此端口并只对应一个面板账号。
INPUT_RULE_COMMENT="anytls-panel-traffic-in-${ANYTLS_PORT}"
OUTPUT_RULE_COMMENT="anytls-panel-traffic-out-${ANYTLS_PORT}"

validate_collector_path_parent() {
    local path="$1"
    local label="$2"
    if [[ "$path" != /* ]]; then
        echo "$label must be an absolute path" >&2
        return 1
    fi
    local parent_dir
    parent_dir=$(dirname "$path")
    if [[ ! -d "$parent_dir" ]]; then
        echo "$label parent directory must already exist" >&2
        return 1
    fi

    local resolved_parent
    resolved_parent=$(realpath "$parent_dir") || return 1
    local candidate component current metadata owner mode
    for candidate in "$parent_dir" "$resolved_parent"; do
        current=""
        local components=()
        IFS='/' read -r -a components <<< "${candidate#/}"
        for component in "${components[@]}"; do
            current="${current}/${component}"
            if ! metadata=$(stat -c '%u %a' "$current" 2>/dev/null); then
                metadata=$(stat -f '%u %Lp' "$current" 2>/dev/null) || return 1
            fi
            read -r owner mode <<< "$metadata"
            if [[ "$owner" != "0" ]] || (( (8#$mode & 8#022) != 0 )); then
                echo "$label parent chain must be root-owned and not group/world writable" >&2
                return 1
            fi
        done
    done
}

acquire_collector_lock() {
    if ! command -v flock >/dev/null 2>&1; then
        echo "flock is required (install util-linux)" >&2
        return 1
    fi
    if [[ -d "${COLLECTOR_LOCK_FILE}" || -L "${COLLECTOR_LOCK_FILE}" ]]; then
        echo "COLLECTOR_LOCK_FILE must be a regular non-symlink file" >&2
        return 1
    fi
    validate_collector_path_parent \
        "${COLLECTOR_LOCK_FILE}" "COLLECTOR_LOCK_FILE" || return 1
    exec 9> "${COLLECTOR_LOCK_FILE}" || return 1
    if ! flock -n 9; then
        echo "another traffic collector instance is already running" >&2
        return 1
    fi
}

# 确保 iptables 规则存在
ensure_iptables() {
    if ! iptables -C INPUT -p tcp --dport "${ANYTLS_PORT}" \
        -m comment --comment "${INPUT_RULE_COMMENT}" >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "${ANYTLS_PORT}" \
            -m comment --comment "${INPUT_RULE_COMMENT}" || return 1
    fi
    if ! iptables -C OUTPUT -p tcp --sport "${ANYTLS_PORT}" \
        -m comment --comment "${OUTPUT_RULE_COMMENT}" >/dev/null 2>&1; then
        iptables -I OUTPUT -p tcp --sport "${ANYTLS_PORT}" \
            -m comment --comment "${OUTPUT_RULE_COMMENT}" || return 1
    fi
}

# 获取流量计数
get_traffic_bytes() {
    local input_rules
    local output_rules
    local in_bytes
    local out_bytes
    if ! input_rules=$(iptables -L INPUT -n -v -x 2>/dev/null); then
        return 1
    fi
    if ! output_rules=$(iptables -L OUTPUT -n -v -x 2>/dev/null); then
        return 1
    fi
    in_bytes=$(printf '%s\n' "${input_rules}" | \
        awk -v marker="${INPUT_RULE_COMMENT}" 'index($0, marker) {sum += $2} END {print sum + 0}')
    out_bytes=$(printf '%s\n' "${output_rules}" | \
        awk -v marker="${OUTPUT_RULE_COMMENT}" 'index($0, marker) {sum += $2} END {print sum + 0}')
    in_bytes=${in_bytes:-0}
    out_bytes=${out_bytes:-0}
    echo $((in_bytes + out_bytes))
}

ensure_collector_id() {
    if [[ -d "${COLLECTOR_ID_FILE}" || -L "${COLLECTOR_ID_FILE}" ]]; then
        echo "COLLECTOR_ID_FILE must be a regular non-symlink file" >&2
        return 2
    fi
    if [[ -z "${COLLECTOR_ID}" ]]; then
        validate_collector_path_parent \
            "${COLLECTOR_ID_FILE}" "COLLECTOR_ID_FILE" || return 1
        if [[ -r "${COLLECTOR_ID_FILE}" ]]; then
            read -r COLLECTOR_ID < "${COLLECTOR_ID_FILE}" || true
        fi
    fi
    if [[ -z "${COLLECTOR_ID}" ]]; then
        COLLECTOR_ID=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \r\n')
        local temp_file="${COLLECTOR_ID_FILE}.tmp.$$"
        if ! (umask 077; printf '%s\n' "${COLLECTOR_ID}" > "${temp_file}"); then
            rm -f -- "${temp_file}"
            return 1
        fi
        if ! mv -f "${temp_file}" "${COLLECTOR_ID_FILE}"; then
            rm -f -- "${temp_file}"
            return 1
        fi
        local persisted_id
        if ! read -r persisted_id < "${COLLECTOR_ID_FILE}" || \
           [[ "${persisted_id}" != "${COLLECTOR_ID}" ]]; then
            echo "failed to persist COLLECTOR_ID" >&2
            return 1
        fi
    fi
    if ! [[ "${COLLECTOR_ID}" =~ ^[A-Za-z0-9._:-]{8,128}$ ]]; then
        echo "COLLECTOR_ID must be 8-128 safe characters" >&2
        return 2
    fi
}

# 上报流量
report_traffic() {
    local bytes=$1
    local payload
    if [[ -n "${ACCOUNT_ID}" ]]; then
        if ! [[ "${ACCOUNT_ID}" =~ ^[1-9][0-9]*$ ]]; then
            echo "ACCOUNT_ID must be a positive integer" >&2
            return 2
        fi
        payload="{\"collector_id\": \"${COLLECTOR_ID}\", \"account_id\": ${ACCOUNT_ID}, \"counter_bytes\": ${bytes}}"
    else
        local password_b64
        password_b64=$(printf '%s' "${PASSWORD}" | base64 | tr -d '\r\n')
        payload="{\"collector_id\": \"${COLLECTOR_ID}\", \"password_b64\": \"${password_b64}\", \"counter_bytes\": ${bytes}}"
    fi
    curl -fsS --connect-timeout 10 --max-time 30 -o /dev/null \
        -X POST "${PANEL_URL}/api/traffic/counter" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -d "${payload}"
}

# 主逻辑
main() {
    acquire_collector_lock || return
    ensure_collector_id || return
    ensure_iptables || return
    local current_bytes
    current_bytes=$(get_traffic_bytes) || return
    report_traffic "${current_bytes}" || return
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
