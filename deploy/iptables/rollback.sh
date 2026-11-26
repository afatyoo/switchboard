#!/bin/sh
# Remove the Switchboard redirect. Clients go straight to Carbonio Proxy again.
# Each failed delete is reported on stderr; the script keeps going and always
# exits 0 so package removal never fails. A rule that is already gone is
# reported too, which is harmless.
try() {
	if ! out=$("$@" 2>&1); then
		echo "switchboard rollback: failed: $* ${out:+($out)}" >&2
	fi
}
for pair in 993:10993 995:10995 465:10465 587:10587 143:10143 110:10110; do
	try iptables -t nat -D PREROUTING -p tcp --dport "${pair%%:*}" -m comment --comment switchboard -j REDIRECT --to-ports "${pair#*:}"
done
if command -v netfilter-persistent >/dev/null; then
	try netfilter-persistent save
fi
# Remove the internal port guard.
try iptables -D INPUT -p tcp -m multiport --dports 10993,10995,10465,10587,10143,10110 -m conntrack ! --ctstate DNAT ! -i lo -m comment --comment switchboard-guard -j DROP
exit 0
