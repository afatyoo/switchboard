#!/bin/sh
# Remove transparent mode rules. HAProxy must use a non-transparent backend again.
# Each failed step is reported on stderr; the script keeps going and always
# exits 0 so package removal never fails.
PORTS=993,995,465,587,143,110
try() {
	if ! out=$("$@" 2>&1); then
		echo "switchboard tproxy rollback: failed: $* ${out:+($out)}" >&2
	fi
}
try iptables -t mangle -D OUTPUT -p tcp -m multiport --dports $PORTS -m addrtype ! --src-type LOCAL -m conntrack --ctstate NEW -m comment --comment switchboard -j CONNMARK --set-mark 0x51
try iptables -t mangle -D OUTPUT -p tcp -m connmark --mark 0x51 -m comment --comment switchboard -j SWITCHBOARD
try iptables -t mangle -D PREROUTING -i lo -p tcp -m socket --transparent -m comment --comment switchboard -j SWITCHBOARD
# rule from older versions; absent on most hosts, so stay quiet about it
iptables -t mangle -D OUTPUT -p tcp -m multiport --sports $PORTS ! -d 127.0.0.0/8 -m comment --comment switchboard -j SWITCHBOARD 2>/dev/null
try iptables -t mangle -F SWITCHBOARD
try iptables -t mangle -X SWITCHBOARD
try ip rule del fwmark 0x51 lookup 151
try ip route flush table 151
try ip addr del "${UPSTREAM_IP:-10.255.255.1}/32" dev lo
exit 0
