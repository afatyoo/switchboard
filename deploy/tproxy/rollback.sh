#!/bin/sh
# Remove transparent mode rules. HAProxy must use a non-transparent backend again.
iptables -t mangle -D OUTPUT -p tcp -m multiport --sports 993,995,465 ! -d 127.0.0.0/8 -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
iptables -t mangle -D PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
iptables -t mangle -F SWITCHBOARD 2>/dev/null; iptables -t mangle -X SWITCHBOARD 2>/dev/null
ip rule del fwmark 0x51 lookup 151 2>/dev/null
ip route flush table 151 2>/dev/null
true
