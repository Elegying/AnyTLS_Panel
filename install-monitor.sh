#!/usr/bin/env bash
# Optional same-host scheduler and pinned proxy verification runtime.
set -Eeuo pipefail

install_probe_core() {
    local artifact digest stage
    case "$(uname -m)" in
        x86_64) artifact=mihomo-linux-amd64-compatible-v1.19.31.gz; digest=04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc ;;
        aarch64|arm64) artifact=mihomo-linux-arm64-v1.19.31.gz; digest=9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4 ;;
        *) return 1 ;;
    esac
    stage="$(mktemp -d)"
    (
        trap 'rm -rf -- "$stage"' EXIT
        curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
            --max-filesize 40000000 "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/$artifact" \
            -o "$stage/core.gz"
        [[ "$(sha256sum "$stage/core.gz" | cut -d' ' -f1)" == "$digest" ]]
        gzip -dc "$stage/core.gz" > "$stage/mihomo"
        install -d -o root -g root -m 755 /usr/local/lib/anytls-tools
        install -o root -g root -m 755 "$stage/mihomo" /usr/local/lib/anytls-tools/mihomo-v1.19.31
    )
}

write_monitor_units() {
    cat > "$UNIT_DIR/$SERVICE_NAME-monitor.service" <<EOF
[Unit]
Description=Bounded AnyTLS node verification
After=$SERVICE_NAME.service
BindsTo=$SERVICE_NAME.service
PartOf=$SERVICE_NAME.service
ConditionPathExists=$PANEL_DIR/node_monitor.py

[Service]
Type=oneshot
User=$SERVICE_USER
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python $PANEL_DIR/node_monitor.py
Environment=ANYTLS_DATABASE=$PANEL_DIR/data/anytls.db
Environment=ANYTLS_SECRET_KEY_FILE=${ANYTLS_SECRET_KEY_FILE:-$PANEL_DIR/data/.secret_key}
Environment=ANYTLS_TRAFFIC_API_TOKEN_FILE=${ANYTLS_TRAFFIC_API_TOKEN_FILE:-$PANEL_DIR/data/.traffic_api_token}
Environment=ANYTLS_ALLOW_PRIVATE_NODE_PROBES=${ANYTLS_ALLOW_PRIVATE_NODE_PROBES:-0}
Environment=ANYTLS_PROXY_VERIFICATION=1
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$PANEL_DIR/data
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=224M
TasksMax=64
CPUQuota=50%
TimeoutStartSec=55s
TimeoutStopSec=3s
KillMode=control-group
EOF
    cat > "$UNIT_DIR/$SERVICE_NAME-monitor.timer" <<EOF
[Unit]
Description=Schedule bounded AnyTLS node verification
BindsTo=$SERVICE_NAME.service
PartOf=$SERVICE_NAME.service
After=$SERVICE_NAME.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=5s
Unit=$SERVICE_NAME-monitor.service

[Install]
WantedBy=timers.target
EOF
}

main() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]]
    PANEL_DIR="${ANYTLS_PANEL_DIR:-/opt/anytls-panel}"
    SERVICE_NAME="${ANYTLS_SERVICE_NAME:-anytls-panel}"
    SERVICE_USER="${ANYTLS_SERVICE_USER:-anytls-panel}"
    UNIT_DIR=/etc/systemd/system
    [[ "$PANEL_DIR" =~ ^/(opt|srv)/[A-Za-z0-9_-]+$ && ! -L "$PANEL_DIR" ]]
    [[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_-]+$ && "$SERVICE_USER" =~ ^[A-Za-z0-9_-]+$ ]]
    [[ "$(id -u "$SERVICE_USER")" -ne 0 && -f "$PANEL_DIR/.anytls-panel-install" ]]
    [[ "$(< "$PANEL_DIR/.anytls-panel-install")" == anytls-panel-managed-v1 ]]
    [[ -f "$PANEL_DIR/node_monitor.py" && -x "$PANEL_DIR/venv/bin/python" ]]
    [[ "${ANYTLS_ALLOW_PRIVATE_NODE_PROBES:-0}" =~ ^[01]$ ]]
    install_probe_core
    write_monitor_units
    install -d -o root -g root -m 755 "$UNIT_DIR/$SERVICE_NAME.service.d"
    printf '%s\n' '[Unit]' "Wants=$SERVICE_NAME-monitor.timer" '[Service]' 'Environment=ANYTLS_PROXY_VERIFICATION=1' \
        > "$UNIT_DIR/$SERVICE_NAME.service.d/monitor.conf"
    systemctl daemon-reload
    systemctl restart "$SERVICE_NAME"
    systemctl enable --now "$SERVICE_NAME-monitor.timer"
    systemctl start "$SERVICE_NAME-monitor.service"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
