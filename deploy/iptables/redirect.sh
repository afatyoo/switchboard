#!/bin/sh
# Redirect external IMAPS/POP3S to the Switchboard HAProxy listeners.
# Local connections to 127.0.0.1:993/995 (HAProxy backend) are not affected.
set -e
iptables -t nat -A PREROUTING -p tcp --dport 993 -m comment --comment switchboard -j REDIRECT --to-ports 10993
iptables -t nat -A PREROUTING -p tcp --dport 995 -m comment --comment switchboard -j REDIRECT --to-ports 10995
