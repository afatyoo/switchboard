# Switchboard

SNI gateway for IMAPS and POP3S in front of Carbonio.

> Status: in development. Manual and LDAP modes work in a single node lab.
> Not production ready.

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
- Use a dedicated LDAP account and `ldaps://` or StartTLS. The account can read
  every domain private key, so treat its password like a private key.

Daily expiry check: install `deploy/systemd/switchboard-check.{service,timer}`
and run `systemctl enable --now switchboard-check.timer`. Results go to the journal.

## Disclaimer

Not affiliated with or endorsed by Zextras. Carbonio is a trademark of its owner.
