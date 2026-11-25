# Switchboard

SNI gateway for IMAPS and POP3S in front of Carbonio.

> Status: concept only. No code yet, nothing has been tested.

## Problem

Carbonio Proxy serves per-domain certificates for HTTPS, but IMAPS and POP3S
always get the infrastructure certificate. Mail clients that connect to a
customer's virtual hostname see a certificate error.

## Idea

Switchboard sits in front of Carbonio Proxy. HAProxy selects the certificate
by SNI, and a small Go tool manages those certificates. Carbonio configuration
stays untouched.

See [docs/CONCEPT.md](docs/CONCEPT.md).

## Disclaimer

Not affiliated with or endorsed by Zextras. Carbonio is a trademark of its owner.
