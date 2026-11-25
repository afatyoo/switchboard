# Lab results (2026-11-25)

Proof of concept on a single Carbonio node. No Carbonio configuration was changed.

## Environment

- Carbonio 26.9.2 (Advanced), Ubuntu 24.04, single server
- HAProxy 2.8.30 from the Ubuntu archive, on the same host
- Infrastructure certificate: wildcard from a public CA
- Two lab domains with certificates from a private lab CA:
  `mail.customer1.test`, `mail.customer2.test`

## Setup

1. HAProxy listens on 10993 (IMAPS) and 10995 (POP3S), config in
   [`deploy/haproxy/haproxy.cfg`](../deploy/haproxy/haproxy.cfg).
2. Default certificate is the Carbonio infrastructure certificate, so clients
   without SNI see exactly what they saw before.
3. Per-domain PEM files (cert + chain + key) in `/etc/haproxy/certs/`,
   owner `root:haproxy`, mode `640`.
4. Backend connects to `127.0.0.1:993/995` over TLS and verifies the
   infrastructure certificate against the system CA store.
5. iptables redirects external 993/995 to the HAProxy ports
   ([`deploy/iptables/redirect.sh`](../deploy/iptables/redirect.sh)),
   persisted with `iptables-persistent`.

## Results

| Test | Result |
|---|---|
| SNI `mail.customer1.test` on 993 and 995 | Served customer1 cert, verifies against lab CA |
| SNI `mail.customer2.test` on 993 and 995 | Served customer2 cert, verifies against lab CA |
| SNI for a name without a file | Served infrastructure cert |
| No SNI | Served infrastructure cert |
| Same tests from another machine via port 993/995 | Same results, redirect works |
| IMAP greeting, CAPABILITY, LOGOUT through gateway | OK, IDLE advertised |
| POP3 greeting and CAPA through gateway | OK |
| IMAP LOGIN, SELECT, APPEND, FETCH with a test account | OK |
| IMAP IDLE push (`EXISTS`) on an open session | OK |
| `systemctl reload haproxy` while IDLE is open | Session survived, push still delivered, NOOP OK |
| Same account through both SNI names | OK |
| POP3 USER/PASS, STAT, RETR | OK |
| 6 wrong passwords, then correct login | Rejected, then accepted (no lockout of gateway) |

Tests ran from a Python client (3.14) on another machine.

## Not tested yet

- IDLE over 30 minutes (HAProxy timeouts are 30m, clients usually re-IDLE every 29m)
- Outlook, Thunderbird and mobile clients
- HAProxy reload during open sessions
- Load test

## Findings

- `zimbraReverseProxyIPLoginLimit` and `zimbraReverseProxyUserLoginLimit` are
  `0` on this server, so Carbonio did not throttle the gateway IP. If they are
  enabled, every login arrives from `127.0.0.1` and one attacker could lock out
  all users. Per IP limits live in HAProxy instead (60 conn/min, 50 concurrent).
- `127.0.0.1` is in `zimbraMailTrustedIP`. The proxy forwards the client IP to
  the mailbox (`XOIP`), and through the gateway that IP is always `127.0.0.1`.
  Carbonio audit logs lose the real client IP. Needs checking whether the
  trusted status changes any auth behavior.
- The wildcard infrastructure certificate does not cover the
  node FQDN (two labels deep). Backend verification uses a name that matches
  the wildcard.

- Carbonio Advanced with 2FA policy rejects the normal account password on
  IMAP/POP3 (`Unsupported 2FA for service Imap`). This happens with or without
  the gateway. Mail clients need an app credential:
  `carbonio auth credential add <account> label <name> service imap,pop3`.
- Carbonio logs `oip=127.0.0.1` for every session through the gateway, so the
  real client IP is lost. Logging and blocking must use HAProxy logs.
- Python 3.13+ rejects a CA without `keyUsage`. Lab CAs must set
  `basicConstraints=CA:TRUE` and `keyUsage=keyCertSign`, leaf certificates
  `extendedKeyUsage=serverAuth`. Switchboard validation should check this.

## Rollback

```sh
deploy/iptables/rollback.sh
systemctl disable --now haproxy
```

Clients connect straight to Carbonio Proxy again. HAProxy and the redirect are
the only changes on the host.
