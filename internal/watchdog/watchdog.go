// Package watchdog keeps mail ports working when Switchboard does not.
//
// Every public port (993, 587, ...) is redirected by iptables to a local
// Switchboard listener. If that listener stops answering, the watchdog removes
// the redirect for that port so clients reach Carbonio directly (with the
// infrastructure certificate) instead of failing. When the listener answers
// again the redirect is restored.
package watchdog

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/afatyoo/switchboard/internal/metrics"
)

// Port is one redirected port.
type Port struct {
	Public int    // port clients connect to
	Local  int    // Switchboard listener
	Check  string // "tls" (implicit TLS listener) or "starttls" (STARTTLS proxy; "banner" is the old name)
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
	// MinFailOpenInterval stops a flapping listener from toggling the
	// redirect: after a fail-open the redirect is not restored until this
	// long has passed, so a port toggles at most once per interval. It never
	// delays fail-open itself. 0 disables it.
	MinFailOpenInterval time.Duration
	// Now returns the current time; nil means time.Now. For tests.
	Now func() time.Time
	Log *log.Logger
	// AfterTick runs after every round, for example to write metrics.
	AfterTick func(w *Watchdog)

	state    map[int]*portState
	lastTick time.Time
}

type portState struct {
	fails, oks int
	open       bool      // redirect active
	up         bool      // last probe succeeded
	failOpens  int       // times the redirect was removed
	openedAt   time.Time // when the redirect was last removed (fail-open began)
	held       bool      // restore is being held back by MinFailOpenInterval
}

func (w *Watchdog) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Collect adds the watchdog's metrics to b.
func (w *Watchdog) Collect(b *metrics.Builder) {
	for _, p := range w.Ports {
		st := w.state[p.Public]
		if st == nil {
			continue
		}
		l := metrics.Labels{"port": strconv.Itoa(p.Public), "listener": strconv.Itoa(p.Local)}
		b.Gauge("switchboard_listener_up", "1 if the Switchboard listener answered the last health probe.", l, boolf(st.up))
		b.Gauge("switchboard_redirect_active", "1 if traffic for the port goes through Switchboard, 0 during fail-open.", metrics.Labels{"port": strconv.Itoa(p.Public)}, boolf(st.open))
		active := 0.0
		if !st.open && !st.openedAt.IsZero() {
			active = w.lastTick.Sub(st.openedAt).Seconds()
		}
		b.Gauge("switchboard_failopen_active_seconds", "Seconds the current fail-open has lasted (since the watchdog removed the redirect), 0 while the redirect is active.", metrics.Labels{"port": strconv.Itoa(p.Public)}, active)
		b.Counter("switchboard_failopen_total", "Times the watchdog removed the redirect since it started.", metrics.Labels{"port": strconv.Itoa(p.Public)}, float64(st.failOpens))
	}
	b.Gauge("switchboard_watchdog_last_tick_timestamp_seconds", "Unix time of the last watchdog round.", nil, float64(w.lastTick.Unix()))
}

func boolf(v bool) float64 {
	if v {
		return 1
	}
	return 0
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
	defer func() {
		w.lastTick = w.now()
		if w.AfterTick != nil {
			w.AfterTick(w)
		}
	}()
	for _, p := range w.Ports {
		st := w.state[p.Public]
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		err := w.Probe(pctx, p)
		cancel()
		st.up = err == nil
		if err != nil {
			st.fails++
			st.oks = 0
			if st.open && st.fails >= w.FailAfter {
				if rerr := w.Firewall.Remove(p); rerr != nil {
					w.Log.Printf("watchdog: port %d: listener %d unhealthy (%v), removing redirect failed: %v", p.Public, p.Local, err, rerr)
					continue
				}
				st.open = false
				st.failOpens++
				st.openedAt = w.now()
				w.Log.Printf("watchdog: port %d: listener %d unhealthy (%v), redirect removed, clients go to Carbonio directly", p.Public, p.Local, err)
			}
			continue
		}
		st.oks++
		st.fails = 0
		if !st.open && st.oks >= w.RecoverAfter {
			if w.MinFailOpenInterval > 0 && !st.openedAt.IsZero() {
				if wait := w.MinFailOpenInterval - w.now().Sub(st.openedAt); wait > 0 {
					if !st.held {
						st.held = true
						w.Log.Printf("watchdog: port %d: listener %d healthy, holding restore for %s (min_failopen_interval)", p.Public, p.Local, wait.Round(time.Second))
					}
					continue
				}
			}
			st.held = false
			if aerr := w.Firewall.Add(p); aerr != nil {
				w.Log.Printf("watchdog: port %d: restoring redirect failed: %v", p.Public, aerr)
				continue
			}
			st.open = true
			w.Log.Printf("watchdog: port %d: listener %d healthy, redirect restored", p.Public, p.Local)
		}
	}
}
