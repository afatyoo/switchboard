# Concept

## Traffic

```
mail client --TLS (SNI)--> Switchboard (HAProxy) --TLS--> Carbonio Proxy
                             ^
                             certificates managed by the Go tool
```

Ports 993 and 995 go to Switchboard. Everything else keeps going to Carbonio.

## Deployment

- Same host as Carbonio Proxy: redirect 993/995 to local ports with iptables.
  Suitable for labs and single server installs.
- Separate host: split by port at the firewall or NAT. Preferred for production.

## Certificate sources

| Mode | How it works |
|---|---|
| `manual` | The admin adds certificate and key files from the command line |
| `ldap` | Domain certificates are read from Carbonio LDAP, read-only |

Both modes share one path: validate, write PEM, check HAProxy config, reload.
A broken certificate is rejected and the previous one stays in place.

## Milestones

1. `v0.1.0`: manual mode, IMAPS and POP3S
2. `v0.2.0`: LDAP mode
3. Later: SMTPS, high availability, dashboard

## Limitations and risks

- Carbonio sees the gateway IP, not the client IP. IP based brute force
  protection may block the gateway and therefore every user.
- STARTTLS (143, 110) and SMTP are not covered.
- Clients without SNI receive the default certificate.
- The gateway holds customer private keys and must be hardened.
- The gateway is a new point of failure.

## To verify in a lab

- Domain certificate and key are readable from LDAP after deployment
- Carbonio login throttling when all connections come from one IP
- Long running IMAP IDLE sessions across HAProxy reloads
- Outlook, Thunderbird and mobile clients
