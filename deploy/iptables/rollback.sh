#!/bin/sh
# Remove the Switchboard redirect. Clients go straight to Carbonio Proxy again.
iptables -t nat -D PREROUTING -p tcp --dport 993 -m comment --comment switchboard -j REDIRECT --to-ports 10993
iptables -t nat -D PREROUTING -p tcp --dport 995 -m comment --comment switchboard -j REDIRECT --to-ports 10995
iptables -t nat -D PREROUTING -p tcp --dport 465 -m comment --comment switchboard -j REDIRECT --to-ports 10465
command -v netfilter-persistent >/dev/null && netfilter-persistent save
