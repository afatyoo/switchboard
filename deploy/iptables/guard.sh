#!/bin/sh
# Drop direct connections to the Switchboard listener ports. Connections that
# arrived through the 993/995/465/587/143/110 redirect have conntrack state
# DNAT and are accepted, as is local traffic (watchdog health checks).
set -e
PORTS=10993,10995,10465,10587,10143,10110
iptables -C INPUT -p tcp -m multiport --dports $PORTS -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP 2>/dev/null ||
  iptables -I INPUT 1 -p tcp -m multiport --dports $PORTS -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP
