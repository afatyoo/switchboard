#!/bin/sh
# Switchboard same-host transparent mode.
# HAProxy connects to Carbonio Proxy with the client's IP as source
# (usesrc clientip). Replies from Carbonio Proxy (sport 993/995) to
# non-local addresses are routed back into the host so HAProxy receives them.
# Carbonio configuration is not touched.
set -e
MARK=0x51
TABLE=151
iptables -t mangle -N SWITCHBOARD 2>/dev/null || iptables -t mangle -F SWITCHBOARD
iptables -t mangle -A SWITCHBOARD -j MARK --set-mark $MARK
iptables -t mangle -A SWITCHBOARD -j ACCEPT
# replies leaving Carbonio Proxy towards a client IP
iptables -t mangle -C OUTPUT -p tcp -m multiport --sports 993,995,465,587,143,110 ! -d 127.0.0.0/8 -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null ||
  iptables -t mangle -A OUTPUT -p tcp -m multiport --sports 993,995,465,587,143,110 ! -d 127.0.0.0/8 -m comment --comment switchboard -j SWITCHBOARD
# the same packets coming back in on lo, matched to HAProxy's transparent socket
iptables -t mangle -C PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null ||
  iptables -t mangle -A PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD
ip rule show | grep -q "fwmark $MARK lookup $TABLE" || ip rule add fwmark $MARK lookup $TABLE priority 100
ip route replace local 0.0.0.0/0 dev lo table $TABLE
