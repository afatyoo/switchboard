// Package watchdog keeps mail ports working when Switchboard does not.
//
// Every public port (993, 587, ...) is redirected by iptables to a local
// Switchboard listener. If that listener stops answering, the watchdog removes
// the redirect for that port so clients reach Carbonio directly (with the
// infrastructure certificate) instead of failing. When the listener answers
// again the redirect is restored.
package watchdog

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// Port is one redirected port.
type Port struct {
	Public int    // port clients connect to
	Local  int    // Switchboard listener
	Check  string // "tls" (implicit TLS listener) or "banner" (STARTTLS proxy)
}

// Firewall adds and removes the redirect rule for a port.
type Firewall interface {
	Has(p Port) (bool, error)
	Add(p Port) error
	Remove(p Port) error
}

// Prober checks whether a local listener is healthy.
type Prober func(ctx context.Context, p Port) error

// Watchdog runs the loop.
type Watchdog struct {
	Ports        []Port
	Firewall     Firewall
	Probe        Prober
	Interval     time.Duration
	FailAfter    int // consecutive failures before removing the redirect
	RecoverAfter int // consecutive successes before restoring it
	Log          *log.Logger

	state map[int]*portState
}

type portState struct {
	fails, oks int
	open       bool // redirect active
}

// Run blocks until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) error {
	if err := w.init(); err != nil {
		return err
	}
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (w *Watchdog) init() error {
	if w.Interval == 0 {
		w.Interval = 5 * time.Second
	}
	if w.FailAfter == 0 {
		w.FailAfter = 3
	}
	if w.RecoverAfter == 0 {
		w.RecoverAfter = 3
	}
	if w.Log == nil {
		w.Log = log.Default()
	}
	w.state = map[int]*portState{}
	for _, p := range w.Ports {
		has, err := w.Firewall.Has(p)
		if err != nil {
			return err
		}
		w.state[p.Public] = &portState{open: has}
	}
	return nil
}

// Tick runs one round of probes and firewall changes.
func (w *Watchdog) Tick(ctx context.Context) {
	if w.state == nil {
		if err := w.init(); err != nil {
			w.Log.Printf("watchdog: init: %v", err)
			return
		}
	}
	for _, p := range w.Ports {
		st := w.state[p.Public]
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := w.Probe(pctx, p)
		cancel()
		if err != nil {
			st.fails++
			st.oks = 0
			if st.open && st.fails >= w.FailAfter {
				if rerr := w.Firewall.Remove(p); rerr != nil {
					w.Log.Printf("watchdog: port %d: listener %d unhealthy (%v), removing redirect failed: %v", p.Public, p.Local, err, rerr)
					continue
				}
				st.open = false
				w.Log.Printf("watchdog: port %d: listener %d unhealthy (%v), redirect removed, clients go to Carbonio directly", p.Public, p.Local, err)
			}
			continue
		}
		st.oks++
		st.fails = 0
		if !st.open && st.oks >= w.RecoverAfter {
			if aerr := w.Firewall.Add(p); aerr != nil {
				w.Log.Printf("watchdog: port %d: restoring redirect failed: %v", p.Public, aerr)
				continue
			}
			st.open = true
			w.Log.Printf("watchdog: port %d: listener %d healthy, redirect restored", p.Public, p.Local)
		}
	}
}

// DefaultProbe connects to 127.0.0.1:<local>. For "tls" it completes a TLS
// handshake; for "banner" it expects a protocol greeting.
func DefaultProbe(ctx context.Context, p Port) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Local)))
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	switch p.Check {
	case "tls":
		// Health only: the certificate is checked elsewhere (switchboard check).
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "watchdog.invalid"})
		return tc.HandshakeContext(ctx)
	case "banner":
		l, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return err
		}
		if !(strings.HasPrefix(l, "220") || strings.HasPrefix(l, "* OK") || strings.HasPrefix(l, "+OK")) {
			return fmt.Errorf("unexpected greeting %q", strings.TrimSpace(l))
		}
		return nil
	}
	return fmt.Errorf("unknown check %q", p.Check)
}
