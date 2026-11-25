#!/bin/sh
# Switchboard same-host transparent mode.
# HAProxy and the STARTTLS proxy connect to Carbonio with the client's IP as
# source (usesrc clientip / IP_TRANSPARENT). Replies on those connections are
# routed back into the host so Switchboard receives them.
#
# Only connections opened by Switchboard are marked (connmark). A client that
# reaches Carbonio directly (watchdog removed the redirect) is not affected,
# so fail-open works. Carbonio configuration is not touched.
set -e
MARK=0x51
TABLE=151
PORTS=993,995,465,587,143,110

iptables -t mangle -N SWITCHBOARD 2>/dev/null || iptables -t mangle -F SWITCHBOARD
iptables -t mangle -A SWITCHBOARD -j MARK --set-mark $MARK
iptables -t mangle -A SWITCHBOARD -j ACCEPT

add() { iptables -t mangle -C "$@" 2>/dev/null || iptables -t mangle -A "$@"; }

# 1. A new local connection to a Carbonio port with a non-local source address
#    can only come from a transparent Switchboard socket: tag the connection.
add OUTPUT -p tcp -m multiport --dports $PORTS -m addrtype ! --src-type LOCAL -m conntrack --ctstate NEW \
  -m comment --comment switchboard -j CONNMARK --set-mark $MARK
# 2. Every packet of a tagged connection (Carbonio's replies included) is routed
#    through table $TABLE, which delivers it locally.
add OUTPUT -p tcp -m connmark --mark $MARK -m comment --comment switchboard -j SWITCHBOARD
# 3. The replies come back in on lo; hand them to the transparent socket.
add PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD

ip rule show | grep -q "fwmark $MARK lookup $TABLE" || ip rule add fwmark $MARK lookup $TABLE priority 100
ip route replace local 0.0.0.0/0 dev lo table $TABLE
