# Switchboard

SNI gateway for IMAP, POP3 and SMTP submission (implicit TLS and STARTTLS) in front of Carbonio.

> Status: v0.1.0, tested on a single Carbonio node (Ubuntu 24.04).
> See [docs/PRODUCTION.md](docs/PRODUCTION.md) before using it in production.

## Install (Debian/Ubuntu)

Download the `.deb` from the [releases](https://github.com/afatyoo/switchboard/releases):

```sh
apt install ./switchboard_0.1.0_amd64.deb
```

The package installs files only. Mail ports keep going straight to Carbonio
until you configure and enable it:

```sh
cp /usr/share/switchboard/config.example.yaml /etc/switchboard/config.yaml
# edit config.yaml, and build /etc/haproxy/haproxy.cfg from
# /usr/share/switchboard/haproxy.cfg.example
systemctl enable --now switchboard-tproxy haproxy switchboard-proxy switchboard-watchdog
```

The watchdog adds the port redirects itself once the listeners answer.
`apt remove switchboard` removes the redirects first, so clients fall back to
Carbonio, then stops the services. `apt purge` also deletes `/etc/switchboard`;
certificates in `/etc/haproxy/certs` are left alone.

## Problem

Carbonio Proxy serves per-domain certificates for HTTPS, but IMAPS and POP3S
always get the infrastructure certificate. Mail clients that connect to a
customer's virtual hostname see a certificate error.

## Idea

Switchboard sits in front of Carbonio Proxy. HAProxy selects the certificate
by SNI, and a small Go tool manages those certificates. Carbonio configuration
stays untouched.

See [docs/CONCEPT.md](docs/CONCEPT.md) and [docs/LAB-RESULTS.md](docs/LAB-RESULTS.md).

## Usage (manual mode)

```sh
make linux                      # builds dist/switchboard-linux-amd64
install -m 755 dist/switchboard-linux-amd64 /usr/local/bin/switchboard
install -D -m 640 config.example.yaml /etc/switchboard/config.yaml

switchboard add mail.customer1.com -cert cert.pem -key key.pem -chain chain.pem
switchboard list
switchboard check               # exit 1 if a certificate is invalid or expiring
switchboard remove mail.customer1.com
```

`add` refuses a certificate when the key does not match, the hostname is not
covered, it is expired or not yet valid, the chain does not verify, or a chain
CA lacks `keyUsage keyCertSign`. Every change runs `haproxy -c` first and is
rolled back if the check fails, then HAProxy is reloaded (open sessions stay up).

## STARTTLS ports (587, 143, 110)

HAProxy cannot answer the plain text part of a STARTTLS session, so
`switchboard proxy` does it: it greets the client, offers only STARTTLS,
terminates TLS with the certificate chosen by SNI, opens STARTTLS to the real
server (with the client IP as source when `transparent: true`) and then
forwards bytes. Login and everything after it stay with Carbonio.

Before TLS it accepts only a handful of commands (SMTP `EHLO HELO STARTTLS NOOP
RSET QUIT`, IMAP `CAPABILITY NOOP STARTTLS LOGOUT`, POP3 `CAPA STLS QUIT`),
limits line length and command count, never advertises PIPELINING and drops the
connection if anything follows STARTTLS in the same packet (command injection).

```sh
install -m 644 deploy/systemd/switchboard-proxy.service /etc/systemd/system/
systemctl enable --now switchboard-proxy
```

## Fail-open watchdog and port guard

`switchboard watchdog` probes every Switchboard listener every 5 seconds (TLS
handshake for 10993/10995/10465, protocol greeting for 10587/10143/10110). After
3 failures it removes that port's redirect, so clients reach Carbonio directly
with the infrastructure certificate instead of failing. After 3 successes it
restores the redirect.

`deploy/iptables/guard.sh` drops direct connections to the 10xxx listener ports
from outside; only redirected traffic and local health checks reach them.

The TPROXY rules mark only connections opened by Switchboard (connmark), so a
client that goes straight to Carbonio is answered normally.

```sh
install -m 644 deploy/systemd/switchboard-watchdog.service /etc/systemd/system/
systemctl enable --now switchboard-watchdog
sh deploy/iptables/guard.sh && netfilter-persistent save
```

See [docs/PRODUCTION.md](docs/PRODUCTION.md) for what is still missing before production.

## Upstream address

HAProxy and the STARTTLS proxy reach Carbonio on `10.255.255.1`, an address
`deploy/tproxy/setup.sh` adds to `lo` (override with `UPSTREAM_IP`). Carbonio
listens on `0.0.0.0`, so nothing changes on its side. Using the public address
instead makes the upstream connection tuple identical to a client's own
connection whenever the kernel picks the same source port, which happened for
about 1.4% of sessions when 1000 clients shared one IP (a large office behind
NAT looks exactly like that).

## Logs

`deploy/rsyslog/30-switchboard.conf` writes `/var/log/switchboard/switchboard.log`
(one line per STARTTLS session with client IP, SNI and result, plus watchdog
events) and `/var/log/switchboard/haproxy.log`, with daily rotation from
`deploy/rsyslog/switchboard.logrotate`. Uncomment the `omfwd` actions to forward
to a central syslog server. Watchdog health probes from localhost are not logged.

## Prometheus metrics and alerts

With `watchdog.metrics_file` set, `switchboard watchdog` writes
`switchboard.prom` for the node_exporter textfile collector every round, so an
existing node_exporter publishes it and Prometheus needs no new scrape job. On
Carbonio the collector directory is `/opt/zextras/zmstat/prometheus/`.

| Metric | Meaning |
|---|---|
| `switchboard_listener_up{port,listener}` | Last health probe succeeded |
| `switchboard_redirect_active{port}` | 1 normal, 0 during fail-open |
| `switchboard_failopen_total{port}` | Fail-open events since the watchdog started |
| `switchboard_certificate_valid{hostname}` | Certificate validates (key, name, chain, dates) |
| `switchboard_certificate_expiry_timestamp_seconds{hostname}` | notAfter |
| `switchboard_sync_last_run_timestamp_seconds`, `switchboard_sync_last_run_success` | LDAP sync status |
| `switchboard_proxy_sessions_total{protocol,result}` | STARTTLS proxy sessions by outcome |
| `switchboard_proxy_sessions_active{protocol}` | Open STARTTLS proxy sessions |

Alert rules: [`deploy/prometheus/switchboard-rules.yml`](deploy/prometheus/switchboard-rules.yml)
(fail-open, listener down, watchdog stale, certificate expiring or invalid,
sync failing or stale, proxy upstream errors). On Carbonio copy it to
`/etc/carbonio/carbonio-prometheus/rules/` and send `SIGHUP` to Prometheus.
Routing alerts to email or chat is Alertmanager's job. On Carbonio, point
Prometheus at the bundled Alertmanager by adding
`/etc/carbonio/carbonio-prometheus/alertmanager/switchboard.yml` with
`- targets: ["localhost:9095"]`, then add a route for `alertname=~"Switchboard.*"`
to Alertmanager's config. The sender must be an existing mailbox, Carbonio
rejects unknown local senders. Use `group_by: [alertname]` on that route: one
HAProxy outage fires two alert names for three ports, and grouping per port
sends six mails instead of two.

```yaml
watchdog:
  metrics_file: /opt/zextras/zmstat/prometheus/switchboard.prom
```

## Self-signed infrastructure certificate

Switchboard works with a self-signed Carbonio infrastructure certificate as
long as customers use their virtual hostnames: they only ever see the public
per-domain certificates. Three settings matter:

1. Backend verification must trust the Carbonio CA. In HAProxy use
   `ca-file /etc/haproxy/carbonio-ca.pem verifyhost <infra hostname>`, in the
   proxy set `upstream_ca` and `upstream_verify_name`. Copy the CA from
   `/opt/zextras/conf/ca/ca.pem` and update the copy if Carbonio's CA changes.
   Never use `verify none`.
2. `default_cert` (clients without SNI or with an unknown name) should be a
   public certificate, not the self-signed infrastructure one.
3. During fail-open clients reach Carbonio directly and see the self-signed
   certificate, so alert on watchdog events.

## LDAP mode

With `mode: ldap`, `switchboard sync` reads every Carbonio domain that has
`zimbraVirtualHostname` and a domain certificate (`zimbraSSLCertificate`,
`zimbraSSLPrivateKey`), validates the certificate for each virtual hostname and
installs it. Upload the certificate once in the Carbonio Admin Panel (or with
`zmdomaincertmgr savecrt`) and IMAPS/POP3S pick it up on the next sync.

```sh
switchboard sync -dry-run       # show the plan
switchboard sync                # apply it (one haproxy check, one reload)
systemctl enable --now switchboard-sync.timer   # every 15 minutes
```

Rules:

- LDAP is only read. If LDAP is unreachable or the bind fails, nothing changes.
- A virtual hostname the certificate does not cover is skipped.
- A hostname installed with `switchboard add` is never overwritten by sync.
  `switchboard remove` hands it back to sync.
- Certificates whose domain lost its certificate or virtual hostname are removed.
  More than `max_remove` removals in one run are refused.
- Reading `zimbraSSLPrivateKey` needs a Carbonio LDAP admin. The built in
  application accounts (`zmpostfix`, `zmamavis`, `zmnginx`) cannot read it, and
  a narrower account would need a custom slapd ACL, which changes Carbonio.
- On the Carbonio node itself, connect over the local socket and read the
  password from Carbonio at run time, so no copy is stored and nothing crosses
  the network:

  ```yaml
  ldap:
    url: ldapi:///run/carbonio/run/ldapi
    bind_dn: uid=zimbra,cn=admins,cn=zimbra
    password_command: [runuser, -u, zextras, --, /opt/zextras/bin/zmlocalconfig, -s, -m, nokey, zimbra_ldap_password]
  ```
- On a separate host, use `ldaps://` or StartTLS and a `password_file` with mode
  `0600`. `sync` warns when it runs over plain `ldap://`.

Daily expiry check: install `deploy/systemd/switchboard-check.{service,timer}`
and run `systemctl enable --now switchboard-check.timer`. Results go to the journal.

## Disclaimer

Not affiliated with or endorsed by Zextras. Carbonio is a trademark of its owner.
