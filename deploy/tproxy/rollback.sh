#!/bin/sh
# Remove transparent mode rules. HAProxy must use a non-transparent backend again.
PORTS=993,995,465,587,143,110
iptables -t mangle -D OUTPUT -p tcp -m multiport --dports $PORTS -m addrtype ! --src-type LOCAL -m conntrack --ctstate NEW -m comment --comment switchboard -j CONNMARK --set-mark 0x51 2>/dev/null
iptables -t mangle -D OUTPUT -p tcp -m connmark --mark 0x51 -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
iptables -t mangle -D PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
# rule from older versions
iptables -t mangle -D OUTPUT -p tcp -m multiport --sports $PORTS ! -d 127.0.0.0/8 -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
iptables -t mangle -F SWITCHBOARD 2>/dev/null; iptables -t mangle -X SWITCHBOARD 2>/dev/null
ip rule del fwmark 0x51 lookup 151 2>/dev/null
ip route flush table 151 2>/dev/null
true
