# Changelog

Every release has a codename from the history of the telephone exchange, in
alphabetical order. See [docs/CODENAMES.md](docs/CODENAMES.md).

## v0.3.0 "Crossbar"

Security fixes from the first audit, session limits on the STARTTLS proxy, and
an alert for a fail-open that lasts. Tested on a Carbonio 26.9 node on Ubuntu
24.04.

### Upgrade notes

- `apt install ./switchboard_0.3.0_amd64.deb` over v0.2.0 restarts the running
  services with the new binary; the configuration is kept.
- Installing the package alone does not install the new firewall rule or the
  updated HAProxy configuration. Run `switchboard setup` again with the flags
  you used before (`-dry-run` previews it). Without it the HAProxy per-IP limit
  still counts the watchdog probe and local users can still reach the listener
  ports.
- The iptables guard now rejects loopback connections from non root users to
  the listener ports (10993, 10995, 10465, 10587, 10143, 10110). The public
  mail ports from localhost are not affected and go straight to Carbonio. A
  local monitoring check that probes a listener port directly must run as root
  or use the public port.
- `proxy.max_sessions` defaults to 20000 sessions (0 = unlimited),
  `proxy.pretls_command_timeout` to 15s, and `proxy.idle_timeout` plus
  `watchdog.min_failopen_interval` stay off, so an existing `config.yaml` keeps
  working as before.

### Security

- A local unprivileged process could force fail-open on a public mail port by
  holding every per-IP slot for 127.0.0.1, the source of the watchdog probe
  (#17). Loopback sources are no longer counted by the STARTTLS proxy per-IP
  limit or tracked by the HAProxy stick tables. Internet clients keep their
  limits. Re-run `switchboard setup` (or update `haproxy.cfg` by hand) to pick
  up the HAProxy change.
- STARTTLS proxy: the client SNI is logged quoted, and only when it is a valid
  hostname (`sni="invalid"` otherwise), so it cannot forge log lines.
  Certificate selection uses the same hostname rule and falls back to the
  default certificate (fixes #19).
- STARTTLS proxy: running out of file descriptors no longer stops it. Transient
  accept errors (EMFILE, ENFILE, ECONNABORTED) are logged and retried with a
  short backoff (fixes #18).
- STARTTLS proxy: in transparent mode, loopback clients are dialed upstream
  without `IP_TRANSPARENT`, so a local session never reaches Carbonio as
  127.0.0.1 through the gateway (part of #21).

- The root watchdog now reads the proxy stats file without following
  symlinks, refuses FIFOs and non regular files, checks the owner is the
  `haproxy` user and caps the size at 1 MiB. The watchdog unit gets
  `MemoryMax=256M` (fixes #20).
- Sync state and files written by `switchboard setup` go through a random
  temp name, fsync and rename, so a planted symlink is never followed and a
  rollback cannot leave a truncated `haproxy.cfg` or `config.yaml` (part of
  #21).
- Local non root processes can no longer connect to the Switchboard listener
  ports over loopback (`guard.sh` rejects them on `OUTPUT`). Without it a local
  user could fill the STARTTLS session limit or HAProxy `maxconn` and make the
  watchdog fail open (#17 follow up). The watchdog runs as root and is not
  affected.

### Added

- `proxy.max_sessions` (default 20000, 0 = unlimited): one session limit for
  all STARTTLS listeners; rejected sessions count as `limited` (#18).
- `proxy.idle_timeout` (default 0, off): close encrypted sessions with no
  traffic in either direction (#18).
- `proxy.pretls_command_timeout` (default 15s): per command wait before
  STARTTLS, inside the overall pre-TLS limit (part of #21).

### Hardening (part of #21)

- CI: pull request builds in `package.yml` run with `contents: read`; only a
  separate tag-triggered `release` job gets `contents: write`. All actions are
  pinned to commit SHAs.
- `deploy/iptables/rollback.sh` and `deploy/tproxy/rollback.sh` report each
  failed delete on stderr instead of ignoring it, and still exit 0.
- New `watchdog.min_failopen_interval` (default 0, off): after a fail-open the
  redirect is not restored until the interval has passed, so a flapping
  listener toggles a port at most once per interval. Fail-open itself is never
  delayed.
- New metric `switchboard_failopen_active_seconds{port}` and alert
  `SwitchboardFailOpenProlonged` for a fail-open lasting over 5 minutes.

## v0.2.0 "Bakelite"

Installation becomes one command, and fail-open now covers the STARTTLS ports
properly. Tested on a Carbonio 26.9 node on Ubuntu 24.04.

### Upgrade notes

- `apt install ./switchboard_0.2.0_amd64.deb` over v0.1.0 restarts the running
  services with the new binary; the configuration is kept.
- Existing configurations with `check: banner` keep working and now get the
  full STARTTLS check. New configurations use `check: starttls`.

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

## v0.1.0 "Almon"

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
