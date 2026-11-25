#!/bin/sh
# Before removal: hand the mail ports back to Carbonio first, then stop.
# On upgrade ($1 = upgrade) nothing is touched; postinst restarts services.
set -e

case "$1" in
    remove|deconfigure)
        # Stop the watchdog first so it does not re-add redirects.
        systemctl disable --now switchboard-watchdog.service >/dev/null 2>&1 || true
        # Fail open: remove the redirects so clients reach Carbonio directly.
        /usr/lib/switchboard/redirect-rollback.sh >/dev/null 2>&1 || true
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
        systemctl disable --now switchboard-sync.timer switchboard-check.timer >/dev/null 2>&1 || true
        systemctl disable --now switchboard-proxy.service >/dev/null 2>&1 || true
        # Stopping this unit runs tproxy-rollback.sh (routing rules, upstream address).
        systemctl disable --now switchboard-tproxy.service >/dev/null 2>&1 || true
        ;;
esac
exit 0
