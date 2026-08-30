#!/bin/bash
# AnyTLS Panel IPv4 端口流量采集器，部署在节点服务器上。
# 定期读取本脚本创建的 iptables 计数规则，并把累计值幂等上报到面板。
#
# 推荐通过 root 私有的环境文件或定时任务环境配置，不要把真实 Token 和密码写入仓库。
# 完整限制和示例见 docs/CONFIGURATION.md 与 docs/OPERATIONS.md。

# ─── 配置 ─────────────────────────────
# PANEL_URL 和 API_TOKEN 必填；推荐同时填写 ACCOUNT_ID。
# PASSWORD 只保留给主 Token 兼容模式，新部署不应使用。
PANEL_URL="${PANEL_URL:-}"
PASSWORD="${PASSWORD:-}"
ACCOUNT_ID="${ACCOUNT_ID:-}"
API_TOKEN="${API_TOKEN:-}"
COLLECTOR_ID="${COLLECTOR_ID:-}"
COLLECTOR_ID_FILE="${COLLECTOR_ID_FILE:-/var/lib/anytls-panel-traffic.id}"
COLLECTOR_LOCK_FILE="${COLLECTOR_LOCK_FILE:-/run/anytls-panel-traffic.lock}"

# ─── iptables 方式 ────────────────────
# 首次运行会添加只计数、不改变 ACCEPT/DROP 决策的 iptables 规则。

ANYTLS_PORT="${ANYTLS_PORT:-443}"  # 修改为你的 anytls 端口
# 一个采集实例必须独占此端口并只对应一个面板账号。
INPUT_RULE_COMMENT="anytls-panel-traffic-in-${ANYTLS_PORT}"
OUTPUT_RULE_COMMENT="anytls-panel-traffic-out-${ANYTLS_PORT}"

usage() {
    cat <<'EOF'
AnyTLS Panel 节点流量采集器

必填环境变量：
  PANEL_URL   HTTPS 面板根地址，例如 https://panel.example.com
  API_TOKEN   与账号匹配的账号级 Token
  ACCOUNT_ID  面板账号 ID（推荐）
  ANYTLS_PORT 该账号独占的 AnyTLS TCP 端口，默认 443

示例：
  PANEL_URL=https://panel.example.com ACCOUNT_ID=1 \
  API_TOKEN=替换为账号级Token ANYTLS_PORT=443 bash traffic_collector.sh

兼容模式可用 PASSWORD 代替 ACCOUNT_ID，但只能配合主 Token，不推荐新部署使用。
EOF
}

current_euid() {
    printf '%s\n' "${EUID:-$(id -u)}"
}

command_is_available() {
    command -v "$1" >/dev/null 2>&1
}

validate_configuration() {
    if [[ -z "$PANEL_URL" ]]; then
        echo "PANEL_URL is required" >&2
        return 2
    fi
    PANEL_URL="${PANEL_URL%/}"
    if [[ "$PANEL_URL" =~ ^https://[^@/?#[:space:]]+$ ]]; then
        :
    elif [[ "$PANEL_URL" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]]; then
        :
    else
        echo "PANEL_URL must be an HTTPS origin without credentials or a path" >&2
        return 2
    fi
    if [[ -z "$API_TOKEN" ]]; then
        echo "API_TOKEN is required" >&2
        return 2
    fi
    if [[ -n "$ACCOUNT_ID" ]]; then
        if ! [[ "$ACCOUNT_ID" =~ ^[1-9][0-9]*$ ]]; then
            echo "ACCOUNT_ID must be a positive integer" >&2
            return 2
        fi
    elif [[ -z "$PASSWORD" ]]; then
        echo "ACCOUNT_ID is required (or PASSWORD for the legacy main-token mode)" >&2
        return 2
    fi
    if ! [[ "$ANYTLS_PORT" =~ ^[0-9]+$ ]] || \
       (( ANYTLS_PORT < 1 || ANYTLS_PORT > 65535 )); then
        echo "ANYTLS_PORT must be an integer between 1 and 65535" >&2
        return 2
    fi
    if [[ "$(current_euid)" -ne 0 ]]; then
        echo "traffic_collector.sh must run as root to read and manage iptables" >&2
        return 2
    fi
    local command_name
    for command_name in awk base64 curl dirname flock iptables mv od realpath stat tr; do
        if ! command_is_available "$command_name"; then
            echo "required command is missing: $command_name" >&2
            return 2
        fi
    done
}

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
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        return 0
    fi
    if [[ $# -gt 0 ]]; then
        echo "unknown argument: $1" >&2
        usage >&2
        return 2
    fi
    validate_configuration || return
    acquire_collector_lock || return
    ensure_collector_id || return
    ensure_iptables || return
    local current_bytes
    current_bytes=$(get_traffic_bytes) || return
    report_traffic "${current_bytes}" || return
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
