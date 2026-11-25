# Changelog

## Unreleased

### Added

- `switchboard setup`: detects the Carbonio node, writes the configuration,
  activates Switchboard and verifies every port, with automatic rollback.
  Flags: `-dry-run`, `-yes`, `-mode`, `-ports`, `-default-cert`, `-extra-ca`,
  `-upstream-ip`, `-timeout`.

### Changed

- Debian package metadata now says MIT.
- Watchdog check for STARTTLS ports is now `starttls` (`banner` still accepted):
  it runs STARTTLS and waits for an answer from Carbonio, at most every
  `watchdog.deep_every` (default 30 s) per port, greeting only in between.

### Fixed

- A broken path from the STARTTLS proxy to Carbonio (wrong upstream name or
  CA, TPROXY rules missing, Carbonio service down) did not trigger fail-open
  on 587, 143 and 110, because the proxy answers the greeting itself.
  `setup` had the same blind spot.

## v0.1.0

First release. Tested on a single Carbonio 26.9 node on Ubuntu 24.04.

### Added

- SNI gateway for Carbonio mail ports without changing Carbonio:
  - HAProxy for implicit TLS: IMAPS 993, POP3S 995, SMTPS 465
  - `switchboard proxy` for STARTTLS: submission 587, IMAP 143, POP3 110
- Real client IP preserved with TPROXY, so Carbonio and Postfix log and limit
  per client as before
- Certificate management:
  - manual mode: `switchboard add | remove | list | check`
  - LDAP mode: `switchboard sync` reads domain certificates and virtual
    hostnames from Carbonio LDAP (read only, `ldapi` and password command
    supported)
  - validation before every change, `haproxy -c` check and rollback
- `switchboard watchdog`: fail-open per port (redirect removed while a listener
  is unhealthy, restored on recovery), Prometheus metrics through the
  node_exporter textfile collector
- Prometheus alert rules, rsyslog and logrotate configuration
- Debian package (`.deb`): installs files only, enables nothing; removal hands
  the ports back to Carbonio first

### Known limits

- IPv4 only; do not publish AAAA records for customer hostnames
- One node; high availability means one Switchboard per Carbonio proxy node
- Carbonio limits apply first (15 IMAP sessions per account and 200 per
  mailbox server by default, 60 s for unauthenticated proxy sessions)
- Not yet tested on Outlook, Apple Mail, Android, iOS or RHEL family systems
