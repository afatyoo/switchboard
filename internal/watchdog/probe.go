package watchdog

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Checker checks Switchboard listeners.
//
//   - "tls": TLS handshake, then the server greeting, which Carbonio sends
//     through HAProxy, so the whole path is checked.
//   - "starttls" (also "banner", the older name): the STARTTLS proxy answers
//     the greeting itself, so a greeting proves nothing about Carbonio. The
//     full check runs STARTTLS and sends one command Carbonio must answer
//     (SMTP EHLO, IMAP NOOP, POP3 CAPA).
//
// The full STARTTLS check opens a session on Carbonio, so it runs at most
// every DeepEvery per port; in between only the greeting is checked. A failed
// full check is repeated on every round until it passes. DeepEvery 0 always
// runs the full check.
type Checker struct {
	DeepEvery time.Duration

	mu       sync.Mutex
	lastDeep map[int]time.Time
}

// Probe implements the watchdog probe function.
func (p *Checker) Probe(ctx context.Context, port Port) error {
	switch port.Check {
	case "tls":
		return probeTLS(ctx, port)
	case "starttls", "banner":
		if !p.deepDue(port.Public) {
			return probeGreeting(ctx, port)
		}
		if err := probeStartTLS(ctx, port); err != nil {
			p.mu.Lock()
			delete(p.lastDeep, port.Public)
			p.mu.Unlock()
			return err
		}
		p.mu.Lock()
		p.lastDeep[port.Public] = time.Now()
		p.mu.Unlock()
		return nil
	}
	return fmt.Errorf("unknown check %q", port.Check)
}

func (p *Checker) deepDue(port int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastDeep == nil {
		p.lastDeep = map[int]time.Time{}
	}
	last, ok := p.lastDeep[port]
	return !ok || p.DeepEvery == 0 || time.Since(last) >= p.DeepEvery
}

// DefaultProbe always runs the full check (used by setup).
func DefaultProbe(ctx context.Context, port Port) error {
	return (&Checker{}).Probe(ctx, port)
}

func dial(ctx context.Context, port Port) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port.Local)))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	return c, nil
}

func probeTLS(ctx context.Context, port Port) error {
	c, err := dial(ctx, port)
	if err != nil {
		return err
	}
	defer c.Close()
	// Health only: certificates are checked by switchboard check.
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "watchdog.invalid"})
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	_, err = greeting(bufio.NewReader(tc))
	return err
}

func probeGreeting(ctx context.Context, port Port) error {
	c, err := dial(ctx, port)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = greeting(bufio.NewReader(c))
	return err
}

// greeting reads the first line and returns the protocol it belongs to.
func greeting(r *bufio.Reader) (string, error) {
	l, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(l, "220"):
		return "smtp", nil
	case strings.HasPrefix(l, "* OK"):
		return "imap", nil
	case strings.HasPrefix(l, "+OK"):
		return "pop3", nil
	}
	return "", fmt.Errorf("unexpected greeting %q", strings.TrimSpace(l))
}

type conv struct {
	w io.Writer
	r *bufio.Reader
}

func (c *conv) send(s string) error {
	_, err := io.WriteString(c.w, s+"\r\n")
	return err
}

// until reads lines until one starts with prefix; a line starting with any
// of bad is an error.
func (c *conv) until(prefix string, bad ...string) error {
	for i := 0; i < 50; i++ {
		l, err := c.r.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, prefix) {
			return nil
		}
		for _, b := range bad {
			if strings.HasPrefix(l, b) {
				return fmt.Errorf("%s", strings.TrimSpace(l))
			}
		}
	}
	return fmt.Errorf("no %q reply", prefix)
}

func probeStartTLS(ctx context.Context, port Port) error {
	c, err := dial(ctx, port)
	if err != nil {
		return err
	}
	defer c.Close()
	r := bufio.NewReader(c)
	proto, err := greeting(r)
	if err != nil {
		return err
	}
	plain := &conv{w: c, r: r}
	switch proto {
	case "smtp":
		if err := plain.send("EHLO watchdog.invalid"); err != nil {
			return err
		}
		if err := plain.until("250 ", "4", "5"); err != nil {
			return fmt.Errorf("EHLO: %w", err)
		}
		if err := plain.send("STARTTLS"); err != nil {
			return err
		}
		if err := plain.until("220", "4", "5"); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	case "imap":
		if err := plain.send("w1 STARTTLS"); err != nil {
			return err
		}
		if err := plain.until("w1 OK", "w1 NO", "w1 BAD"); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	case "pop3":
		if err := plain.send("STLS"); err != nil {
			return err
		}
		if err := plain.until("+OK", "-ERR"); err != nil {
			return fmt.Errorf("STLS: %w", err)
		}
	}

	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "watchdog.invalid"})
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	// From here every reply comes from Carbonio.
	sec := &conv{w: tc, r: bufio.NewReader(tc)}
	var ferr error
	switch proto {
	case "smtp":
		if ferr = sec.send("EHLO watchdog.invalid"); ferr == nil {
			ferr = sec.until("250 ", "4", "5")
		}
		_ = sec.send("QUIT")
	case "imap":
		if ferr = sec.send("w2 NOOP"); ferr == nil {
			ferr = sec.until("w2 OK", "w2 NO", "w2 BAD", "* BYE")
		}
		_ = sec.send("w3 LOGOUT")
	case "pop3":
		if ferr = sec.send("CAPA"); ferr == nil {
			ferr = sec.until("+OK", "-ERR")
		}
		_ = sec.send("QUIT")
	}
	if ferr != nil {
		return fmt.Errorf("no answer from Carbonio after STARTTLS: %w", ferr)
	}
	return nil
}
