# Production readiness

What has to be true before Switchboard serves real customers, and where each
item stands. Status: `done`, `partial`, `open`.

## Phase 1: before the first customer

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Fail-open watchdog | done | `switchboard watchdog` removes the redirect for a port whose listener stops answering, so clients reach Carbonio directly (infrastructure certificate) instead of failing. Re-adds it after recovery. |
| 2 | IPv6 | partial | Not supported. Listeners bind IPv4 only. Do not publish AAAA records for customer hostnames while Switchboard is in front, or add ip6tables and TPROXY rules first. |
| 3 | Internal ports closed | done | `deploy/iptables/guard.sh` drops direct connections to 10xxx unless they arrived through the redirect. |
| 4 | Monitoring and alerts | done | Metrics and 10 alert rules; Alertmanager email route tested end to end (alert delivered to a mailbox); logs in `/var/log/switchboard/` with rotation and an optional central syslog forward. |
| 5 | Brute force protection | partial | Carbonio sees the real client IP (TPROXY), so its own limits and fail2ban on its logs work. Tune HAProxy and proxy per IP limits to real traffic. |
| 6 | Load, soak and failure tests | partial | Done: reboot, fail-open, 2000 concurrent TLS sessions, 140 logged-in IDLE sessions for 5 minutes across a reload, TLS 1.2/1.3 on all ports, Python, curl, openssl and Thunderbird clients. Open: multi day soak, Outlook, Apple Mail, Android, iOS, devices. Carbonio limits apply first: 15 IMAP sessions per account and 200 per mailbox server by default, 60 s for unauthenticated sessions in its proxy. |
| 7 | Security review of the STARTTLS proxy | partial | Go fuzz targets for SMTP, IMAP, POP3 client parsers and upstream parsers (no panics, no STARTTLS accepted with trailing data, bounded responses; seeds run in CI). Open: longer fuzz runs, external review. |

## Phase 2: operations

| # | Item | Status | Notes |
|---|---|---|---|
| 8 | Packaging and upgrades | open | `.deb` or install script, uninstall, upgrade procedure, behaviour across Carbonio upgrades, runbook. |
| 9 | High availability | open | Run Switchboard on every Carbonio proxy node (same host mode) behind the existing load balancer or DNS. |
| 10 | Release engineering | open | Tags, signed builds, `govulncheck` and `staticcheck` in CI, dependency updates. |

## Phase 3: business

| # | Item | Status | Notes |
|---|---|---|---|
| 11 | Vendor support | open | Ask Zextras how an extra component on proxy nodes affects support. |
| 12 | License | open | Repository is public without a license. |
| 13 | LDAP credential | partial | Sync needs the Carbonio LDAP admin DN (no read only account without a custom ACL). Same host mode reads it from localconfig over `ldapi`, no stored copy. |
