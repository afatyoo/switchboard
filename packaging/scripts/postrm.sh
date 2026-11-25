#!/bin/sh
# After removal. purge also deletes Switchboard's own configuration and state.
# Certificates in the HAProxy directory and /etc/haproxy/haproxy.cfg belong to
# the admin and are never deleted.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$1" = "purge" ]; then
    rm -rf /etc/switchboard /var/lib/switchboard /run/switchboard
fi
exit 0
