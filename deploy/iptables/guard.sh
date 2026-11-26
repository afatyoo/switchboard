#!/bin/sh
# Drop direct connections to the Switchboard listener ports. Connections that
# arrived through the 993/995/465/587/143/110 redirect have conntrack state
# DNAT and are accepted, as is local traffic from root (watchdog health checks).
# Other local users may not reach the listeners over loopback: they could fill
# session limits and make the watchdog fail open. They can still use the public
# ports, which go straight to Carbonio.
set -e
PORTS=10993,10995,10465,10587,10143,10110
iptables -C INPUT -p tcp -m multiport --dports $PORTS -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP 2>/dev/null ||
  iptables -I INPUT 1 -p tcp -m multiport --dports $PORTS -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP
iptables -C OUTPUT -o lo -p tcp -m multiport --dports $PORTS -m owner ! --uid-owner 0 -m comment --comment switchboard-guard -j REJECT --reject-with tcp-reset 2>/dev/null ||
  iptables -I OUTPUT 1 -o lo -p tcp -m multiport --dports $PORTS -m owner ! --uid-owner 0 -m comment --comment switchboard-guard -j REJECT --reject-with tcp-reset
