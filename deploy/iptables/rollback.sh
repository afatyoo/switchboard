#!/bin/sh
# Remove the Switchboard redirect. Clients go straight to Carbonio Proxy again.
iptables -t nat -D PREROUTING -p tcp --dport 993 -m comment --comment switchboard -j REDIRECT --to-ports 10993
iptables -t nat -D PREROUTING -p tcp --dport 995 -m comment --comment switchboard -j REDIRECT --to-ports 10995
iptables -t nat -D PREROUTING -p tcp --dport 465 -m comment --comment switchboard -j REDIRECT --to-ports 10465
iptables -t nat -D PREROUTING -p tcp --dport 587 -m comment --comment switchboard -j REDIRECT --to-ports 10587
iptables -t nat -D PREROUTING -p tcp --dport 143 -m comment --comment switchboard -j REDIRECT --to-ports 10143
iptables -t nat -D PREROUTING -p tcp --dport 110 -m comment --comment switchboard -j REDIRECT --to-ports 10110
command -v netfilter-persistent >/dev/null && netfilter-persistent save
# Remove the internal port guard.
iptables -D INPUT -p tcp -m multiport --dports 10993,10995,10465,10587,10143,10110 -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP 2>/dev/null
