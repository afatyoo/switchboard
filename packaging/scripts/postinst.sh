#!/bin/sh
# Install or upgrade. Nothing is enabled or started on a fresh install: the
# admin decides when Switchboard takes over the mail ports.
set -e

if getent group haproxy >/dev/null 2>&1; then
    chgrp haproxy /etc/switchboard 2>/dev/null || true
fi

systemctl daemon-reload >/dev/null 2>&1 || true

# On upgrade, restart only what is already running so the new binary is used.
if [ "$1" = "configure" ] && [ -n "$2" ]; then
    for u in switchboard-proxy switchboard-watchdog; do
        if systemctl is-active --quiet "$u"; then
            systemctl restart "$u" || true
        fi
    done
fi

if [ "$1" = "configure" ] && [ -z "$2" ]; then
    cat <<'EOF'

Switchboard is installed but not active. Mail ports still go straight to Carbonio.
Next steps: /usr/share/doc/switchboard/README.md
  1. cp /usr/share/switchboard/config.example.yaml /etc/switchboard/config.yaml
  2. adapt /etc/haproxy/haproxy.cfg from /usr/share/switchboard/haproxy.cfg.example
  3. systemctl enable --now switchboard-tproxy haproxy switchboard-proxy switchboard-watchdog

EOF
fi
exit 0
