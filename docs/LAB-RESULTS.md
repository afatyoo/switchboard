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

## Transparent mode (real client IP in Carbonio)

Without it, Carbonio logs `oip=127.0.0.1` for every session. With TPROXY,
HAProxy connects to Carbonio Proxy using the client IP as source, still
without any Carbonio change.

- HAProxy backend: `server proxy1 HOST_IP:993 source 0.0.0.0 usesrc clientip`
  (a host address, not 127.0.0.1) and `setcap cap_net_admin,cap_net_raw`
  in `global`. Capabilities need a restart, not a reload.
- Policy routing ([`deploy/tproxy/setup.sh`](../deploy/tproxy/setup.sh)):
  replies from sport 993/995 to non-local addresses get mark `0x51`,
  `ip rule fwmark 0x51 lookup 151`, table 151 has `local 0.0.0.0/0 dev lo`,
  and `-m socket --transparent` on `lo` keeps them going to HAProxy.
- Persisted with [`switchboard-tproxy.service`](../deploy/systemd/switchboard-tproxy.service).

| Test | Result |
|---|---|
| Full test suite (16 checks) | All pass |
| Carbonio `mailbox.log` | `oip=` shows the real client IP |
| Reboot | HAProxy, redirect, mangle rules and ip rule come back; all tests pass once Carbonio is up |

With the real IP visible, Carbonio's own per IP login limits can be enabled
again. Remaining risk: HAProxy picks a random source port per backend
connection (`clientip`, not `client`), so a conntrack collision with the
client's own connection is possible but unlikely.

## switchboard CLI (manual mode)

| Test | Result |
|---|---|
| `add` valid certificate for a new domain | Installed, HAProxy reloaded, SNI serves it |
| `add` with certificate for another hostname | Rejected |
| `add` with non matching key | Rejected |
| `add` with hostname `../../etc/x` | Rejected |
| `add` certificate with 10 days left | Installed with expiry warning |
| `check` with an expiring certificate | Exit 1, listed as warning |
| `remove` | File gone, SNI falls back to default certificate |
| Staging files after all operations | None left |

## LDAP mode

Lab domain with two virtual hostnames, `mail.` covered by the certificate and
`webmail.` not, certificate saved with `zmdomaincertmgr savecrt`.

| Test | Result |
|---|---|
| `sync -dry-run` | Plan shown, nothing changed |
| First `sync` | `mail.` installed, `webmail.` skipped (not covered), SNI serves it |
| Second `sync` | No changes, no reload |
| Certificate renewed in Carbonio | `sync` updates the file |
| Wrong LDAP password | Bind error, exit 1, installed file untouched |
| `switchboard add` on a synced hostname | Manual takes over, sync skips it |
| `switchboard remove` on it | Sync installs it again on the next run |
| Domain certificate cleared in Carbonio | `sync` removes the file, SNI falls back to default |
| Manually added hostnames | Never touched by sync |

The lab bound as the Carbonio admin LDAP user over plain `ldap://` on the same
host. Production should use a dedicated read-only account and TLS.

## LDAP over the local socket

| Test | Result |
|---|---|
| Built in accounts `zmpostfix`, `zmamavis`, `zmnginx` reading domain certificates | No access, admin DN required |
| `sync` over `ldapi:///run/carbonio/run/ldapi` | Works, no TCP connection to 389 |
| Password from `zmlocalconfig` via `password_command` | Works, stored copy removed |

The Carbonio LDAP on the lab node does not offer StartTLS (`ldap_starttls_supported = 0`).

## SMTPS (port 465)

HAProxy frontend on 10465, backend to Postfix 465 with `usesrc clientip`,
iptables redirect 465 to 10465, TPROXY mark extended to source port 465.
Postfix on 465 uses `smtpd_relay_restrictions = permit_sasl_authenticated,reject`,
so `mynetworks` does not allow relay on this port.

| Test | Result |
|---|---|
| SNI `mail.customer1.test` and lab domain on 465 | Domain certificate served |
| AUTH and send through the gateway | OK |
| Unauthenticated relay attempt | Rejected `554 5.7.1 Access denied` |
| Postfix log | `connect from unknown[<real client IP>]` |
| IMAP/POP3 regression suite after the change | All pass |

## STARTTLS proxy (587, 143, 110)

`switchboard proxy` as systemd service (user `haproxy`, `CAP_NET_ADMIN`),
iptables redirect 587/143/110 to 10587/10143/10110, TPROXY mark extended to
those source ports.

| Test | Result |
|---|---|
| SMTP: AUTH not offered before STARTTLS, offered by Postfix after | OK |
| SMTP STARTTLS with SNI, AUTH, send | Customer certificate, OK |
| SMTP unauthenticated relay | Rejected by Postfix |
| IMAP: LOGINDISABLED before STARTTLS, STARTTLS with SNI, LOGIN, SELECT | OK |
| POP3: STLS with SNI, USER/PASS, STAT | OK |
| Postfix submission log | `connect from unknown[<real client IP>]` |
| Carbonio mailbox log | `oip=<real client IP>` |
| Regression: 993/995 suite, 465 suite | All pass |
| Unit tests: injected data after STARTTLS, long lines, command limit, per IP limit | Rejected |

## Fail-open watchdog and port guard

| Test | Result |
|---|---|
| Direct connection from outside to 10993 and 10587 | Dropped by guard |
| Public ports with guard active | Customer certificate, all suites pass |
| HAProxy stopped | After about 15 s redirects for 993/995/465 removed; clients get the infrastructure certificate from Carbonio directly |
| HAProxy started again | Redirects restored, customer certificate again |
| STARTTLS proxy stopped | Redirects for 587/143/110 removed; STARTTLS answered by Carbonio with the infrastructure certificate |
| STARTTLS proxy started again | Redirects restored |

First attempt found a bug: the old TPROXY rule routed every reply from ports
993/587/... back into the host, including replies to clients that reached
Carbonio directly, so fail-open did not work. The rule now marks only
connections opened by Switchboard (CONNMARK on new local connections with a
non-local source address).

## Self-signed infrastructure certificate

Wildcard infrastructure certificate backed up (files, keystores, LDAP values),
then Carbonio's own self-signed certificate deployed with
`zmcertmgr deploycrt self` and the Carbonio systemd targets restarted.
Measured interruption on the node: SMTP about 5 s, IMAP about 15 to 20 s.

| Test | Result |
|---|---|
| Switchboard before changing its backend settings | Client TLS with customer certificate, then upstream verification fails (`valid for <infra host>, not <old name>`); no fallback to unverified |
| Backend switched to Carbonio CA (`ca-file`, `upstream_ca`) | 993/995 suite, 465 suite and 587/143/110 suite all pass |
| Customer hostname on 993 | Public certificate, verify OK |
| No SNI | `default_cert` (public), not the self-signed one |
| Port 25 | Self-signed infrastructure certificate from Postfix (server to server, opportunistic TLS) |
| HAProxy stopped (fail-open) | Client reaches Carbonio and gets the self-signed certificate, verify error 20 |
| HAProxy started | Customer certificate, verify OK |
| Real client IP in Carbonio | Still logged |

## Rollback

```sh
systemctl disable --now switchboard-tproxy   # removes TPROXY routing
deploy/iptables/rollback.sh                  # removes 993/995 redirect
systemctl disable --now haproxy
```

Clients connect straight to Carbonio Proxy again. HAProxy and the redirect are
the only changes on the host.
