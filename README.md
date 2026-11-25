<h1 align="center">Switchboard</h1>

<p align="center">
  Per-domain TLS certificates for Carbonio mail ports, without changing Carbonio.
</p>

<p align="center">
  <a href="https://github.com/afatyoo/switchboard/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/afatyoo/switchboard"></a>
  <a href="https://github.com/afatyoo/switchboard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/afatyoo/switchboard/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Go" src="https://img.shields.io/github/go-mod/go-version/afatyoo/switchboard">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Ubuntu%2022.04%20%7C%2024.04-orange">
</p>

---

Switchboard sits in front of a Carbonio node and gives every customer domain
its own certificate on IMAP, POP3 and SMTP submission, the same way Carbonio
already does for webmail. Mail clients that connect to `mail.customer.com`
get the `mail.customer.com` certificate instead of a certificate warning.

> **Status:** v0.1.0, tested on a single Carbonio 26.9 node on Ubuntu 24.04.
> Read [docs/PRODUCTION.md](docs/PRODUCTION.md) before using it in production.

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Monitoring and logs](#monitoring-and-logs)
- [Operations](#operations)
- [Security](#security)
- [Limitations](#limitations)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

## Why

Carbonio selects a certificate by SNI for HTTPS only. IMAPS, POP3S and SMTP
always present the infrastructure certificate, so a customer who sets up
their mail client with their own virtual hostname sees a certificate error.
The usual workarounds are one multi-SAN certificate that must be reissued
for every new customer, or telling every customer to use the provider's
hostname. Switchboard removes the need for either.

## How it works

```text
                         ┌──────────────── Carbonio node ─────────────────┐
mail client              │                                                │
 SNI: mail.customer.com  │  993/995/465 ─► HAProxy ────────┐              │
 ───────────────────────►│                                 ├─► Carbonio   │
                         │  587/143/110 ─► switchboard ────┘   proxy/MTA  │
                         │                 proxy (STARTTLS)               │
                         │      ▲ per-domain certificate, chosen by SNI   │
                         │      └ manual (switchboard add) or LDAP sync   │
                         └────────────────────────────────────────────────┘
```

1. iptables redirects the public mail ports to Switchboard's listeners.
2. HAProxy (implicit TLS) or `switchboard proxy` (STARTTLS) completes the TLS
   handshake with the certificate that matches the client's SNI.
3. A new, verified TLS connection goes to Carbonio, using the client's IP as
   source address (TPROXY), so Carbonio and Postfix see and log the real client.
4. Authentication, mailbox access and mail delivery stay entirely with Carbonio.
5. If a Switchboard listener stops answering, the watchdog removes that port's
   redirect and clients reach Carbonio directly (fail-open).

## Features

- **All client mail ports:** IMAPS 993, POP3S 995, SMTPS 465 through HAProxy;
  submission 587, IMAP 143, POP3 110 (STARTTLS) through a small Go proxy.
- **No Carbonio changes:** no edits to its proxy templates, Postfix or LDAP.
- **Real client IP** preserved end to end with TPROXY.
- **Two certificate sources:**
  - *manual:* `switchboard add mail.customer.com -cert … -key …`
  - *LDAP:* reads domain certificates and virtual hostnames from Carbonio, so a
    certificate uploaded in the Admin Panel reaches IMAP, POP3 and SMTP too.
- **Safe changes:** every certificate is validated (key, hostname, dates,
  chain) and every change is checked with `haproxy -c` and rolled back on failure.
- **Fail-open watchdog** per port.
- **Prometheus metrics and alert rules**, rsyslog and logrotate configuration.
- **Debian package** that installs files only and hands the ports back to
  Carbonio on removal.

## Requirements

- Ubuntu 22.04 or 24.04, x86_64
- Carbonio on the same node (single node or a proxy node)
- HAProxy 2.4 or newer, iptables, iproute2 (pulled in by the package)
- IPv4 for the customer hostnames (see [Limitations](#limitations))

## Installation

Download the package from the [latest release](https://github.com/afatyoo/switchboard/releases/latest)
and check it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

```bash
sudo apt install ./switchboard_0.1.0_amd64.deb
```

The package enables nothing. Mail ports keep going straight to Carbonio until
you configure Switchboard and start it:

```bash
sudo cp /usr/share/switchboard/config.example.yaml /etc/switchboard/config.yaml
```

Edit `/etc/switchboard/config.yaml`, build `/etc/haproxy/haproxy.cfg` from
`/usr/share/switchboard/haproxy.cfg.example`, then:

```bash
sudo systemctl enable --now switchboard-tproxy haproxy switchboard-proxy switchboard-watchdog
```

The watchdog adds the port redirects by itself once the listeners answer.

## Configuration

All settings live in `/etc/switchboard/config.yaml`; the annotated example is
[`config.example.yaml`](config.example.yaml). The parts that matter most:

| Setting | Purpose |
|---|---|
| `mode` | `manual` or `ldap` |
| `cert_dir` | Certificate directory shared by HAProxy and the proxy |
| `ldap.*` | LDAP sync source (`ldapi:///run/carbonio/run/ldapi` on the Carbonio node) |
| `proxy.*` | STARTTLS listeners, upstream address and verification name |
| `watchdog.*` | Fail-open thresholds and the Prometheus metrics file |

**Upstream address.** HAProxy and the proxy reach Carbonio on `10.255.255.1`,
an address `switchboard-tproxy` adds to `lo`. Using the public address instead
causes conntrack collisions when many clients share one IP (an office behind
NAT).

**Self-signed infrastructure certificate.** Supported: customers only ever see
their public per-domain certificates. Point HAProxy's `ca-file` and the
proxy's `upstream_ca` at Carbonio's CA (`/opt/zextras/conf/ca/ca.pem`) and use a
public certificate as `default_cert`. During fail-open clients see the
self-signed certificate, so keep the fail-open alert on.

## Usage

| Command | What it does |
|---|---|
| `switchboard add HOST -cert F -key F [-chain F]` | Validate and install a certificate |
| `switchboard remove HOST` | Remove a certificate |
| `switchboard list` | Show installed certificates and their status |
| `switchboard check` | Validate all certificates, exit 1 on problems |
| `switchboard sync [-dry-run]` | LDAP mode: install certificates from Carbonio |
| `switchboard proxy` | Run the STARTTLS proxy (systemd service) |
| `switchboard watchdog` | Run the fail-open watchdog and metrics (systemd service) |
| `switchboard version` | Print the version |

Example, manual mode:

```bash
sudo switchboard add mail.customer.com -cert cert.pem -key key.pem -chain chain.pem
sudo switchboard list
```

Example, LDAP mode, after uploading the domain certificate in Carbonio:

```bash
sudo switchboard sync -dry-run
sudo systemctl enable --now switchboard-sync.timer
```

Sync only reads LDAP, never overwrites a manually added hostname, skips names
the certificate does not cover, and refuses to remove more than `max_remove`
certificates in one run.

## Monitoring and logs

**Metrics.** With `watchdog.metrics_file` set, the watchdog writes
`switchboard.prom` for the node_exporter textfile collector, so no new scrape
job is needed. On Carbonio the directory is `/opt/zextras/zmstat/prometheus/`.

| Metric | Meaning |
|---|---|
| `switchboard_redirect_active{port}` | 1 normal, 0 during fail-open |
| `switchboard_listener_up{port,listener}` | Last health probe succeeded |
| `switchboard_certificate_valid{hostname}` | Certificate validates |
| `switchboard_certificate_expiry_timestamp_seconds{hostname}` | Expiry time |
| `switchboard_sync_last_run_success` | LDAP sync status |
| `switchboard_proxy_sessions_total{protocol,result}` | STARTTLS sessions by outcome |

**Alerts.** Ten rules in
[`/usr/share/switchboard/prometheus/switchboard-rules.yml`](deploy/prometheus/switchboard-rules.yml):
fail-open, listener down, watchdog stale, certificate expiring or invalid,
sync failing, proxy upstream errors. On Carbonio copy the file to
`/etc/carbonio/carbonio-prometheus/rules/`. To get them by email, add
`/etc/carbonio/carbonio-prometheus/alertmanager/switchboard.yml` with
`- targets: ["localhost:9095"]` and a route for `alertname=~"Switchboard.*"`
(group by `alertname`, sender must be an existing mailbox).

**Logs.** Install `/usr/share/switchboard/rsyslog/30-switchboard.conf` and the
logrotate file to get `/var/log/switchboard/switchboard.log` (one line per
STARTTLS session with client IP, SNI and result, plus watchdog events) and
`/var/log/switchboard/haproxy.log`. Uncomment `omfwd` to forward to a central
syslog server.

## Operations

| Task | How |
|---|---|
| Hand ports back to Carbonio now | `sudo systemctl stop switchboard-watchdog && sudo /usr/lib/switchboard/redirect-rollback.sh` |
| Upgrade | `sudo apt install ./switchboard_<new>_amd64.deb` (running services restart) |
| Uninstall | `sudo apt remove switchboard` (removes redirects first, then stops services) |
| Remove everything | `sudo apt purge switchboard` (also deletes `/etc/switchboard`; certificates stay) |

## Security

- The pre-TLS part of STARTTLS accepts a minimal command set, limits line
  length and command count, never offers PIPELINING and drops connections that
  send data after STARTTLS (command injection). The parsers are fuzzed.
- Backend connections to Carbonio are always verified; there is no
  `verify none` fallback.
- TLS 1.2 is the minimum on every port.
- Direct access to the internal listener ports is blocked.
- LDAP mode needs the Carbonio LDAP admin DN, because the built-in application
  accounts cannot read domain private keys. On the Carbonio node, use `ldapi`
  with `password_command` so no copy of the password is stored.
- Certificate files are `root:haproxy 0640`.

Report security issues privately to the maintainer rather than in a public issue.

## Limitations

- IPv4 only. Do not publish AAAA records for customer hostnames.
- One node. For several Carbonio proxy nodes, run Switchboard on each.
- Carbonio limits apply first: 15 IMAP sessions per account and 200 per mailbox
  server by default, 60 s for unauthenticated proxy sessions.
- Not yet tested with Outlook, Apple Mail, Android, iOS, or on RHEL family
  systems (`.rpm` is planned).

## Development

```bash
make vet test        # go vet, gofmt, unit tests with -race
make linux           # dist/switchboard-linux-amd64
```

```bash
go test ./internal/starttls/ -run '^$' -fuzz FuzzSMTPClient -fuzztime 60s
```

```bash
go run ./tools/loadtest -host <ip> -mode starttls -n 500 -hold 3m
```

Packages are built by the `package` workflow on every pull request; pushing a
`v*` tag publishes a GitHub release with the `.deb`, the binary and checksums.

## Documentation

- [docs/CONCEPT.md](docs/CONCEPT.md) – design
- [docs/LAB-RESULTS.md](docs/LAB-RESULTS.md) – every lab test and its result
- [docs/PRODUCTION.md](docs/PRODUCTION.md) – production readiness checklist
- [CHANGELOG.md](CHANGELOG.md)

## License

No open source license has been chosen yet. All rights reserved by the author
until a license file is added.

Switchboard is not affiliated with or endorsed by Zextras. Carbonio is a
trademark of its owner.
