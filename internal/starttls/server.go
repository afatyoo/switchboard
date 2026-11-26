// Package starttls is a STARTTLS aware TLS proxy for SMTP submission, IMAP
// and POP3. It answers the plain text part of the session itself, terminates
// TLS with a certificate chosen by SNI, opens STARTTLS to the real server and
// then forwards bytes unchanged. Authentication and everything after it stay
// with the real server.
package starttls

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Listener serves one protocol on one address.
type Listener struct {
	Proto       Protocol
	Listen      string
	Upstream    string
	Banner      string
	Certs       *Certs
	UpstreamTLS *tls.Config // ServerName and RootCAs for the real server
	Transparent bool        // dial upstream with the client IP as source (TPROXY)
	MaxPerIP    int
	Log         *log.Logger
	Stats       *Stats // optional, shared between listeners

	// Sessions is the process wide session limit shared by all listeners.
	// Nil means unlimited.
	Sessions *SessionLimit

	PreTLSTimeout time.Duration
	// PreTLSCommandTimeout bounds the wait for each plain text command, on
	// top of PreTLSTimeout for the whole pre-TLS phase. Zero means 15 s.
	PreTLSCommandTimeout time.Duration
	HandshakeTimeout     time.Duration
	// IdleTimeout closes a piped session after no traffic in either
	// direction for this long. Zero disables it, so IMAP IDLE is unaffected.
	IdleTimeout time.Duration

	mu    sync.Mutex
	perIP map[string]int
}

// Serve accepts connections until ctx is cancelled.
func (l *Listener) Serve(ctx context.Context) error {
	if l.PreTLSTimeout == 0 {
		l.PreTLSTimeout = 60 * time.Second
	}
	if l.PreTLSCommandTimeout == 0 {
		l.PreTLSCommandTimeout = 15 * time.Second
	}
	if l.HandshakeTimeout == 0 {
		l.HandshakeTimeout = 15 * time.Second
	}
	if l.Log == nil {
		l.Log = log.Default()
	}
	// IPv4 only, like the HAProxy listeners: IPv6 is not supported yet and a
	// dual-stack socket would bypass the iptables (IPv4) guard.
	ln, err := net.Listen("tcp4", l.Listen)
	if err != nil {
		return err
	}
	return l.serve(ctx, ln)
}

func (l *Listener) serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	l.Log.Printf("%s: listening on %s, upstream %s", l.Proto.Name(), ln.Addr(), l.Upstream)
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !transientAcceptErr(err) {
				return err
			}
			// fd exhaustion and similar conditions clear up as sessions end:
			// back off and keep serving instead of exiting (issue #18).
			if backoff == 0 {
				l.Log.Printf("%s: accept: %v, backing off", l.Proto.Name(), err)
				backoff = minAcceptBackoff
			} else if backoff *= 2; backoff > maxAcceptBackoff {
				backoff = maxAcceptBackoff
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		go l.handle(c)
	}
}

const (
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

// transientAcceptErr reports whether Accept may succeed later. A closed
// listener is permanent; resource exhaustion and per connection errors are
// retried.
func transientAcceptErr(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var ne net.Error
	//nolint:staticcheck // Temporary is deprecated but still set for accept errors.
	return errors.As(err, &ne) && (ne.Timeout() || ne.Temporary())
}

// SessionLimit caps concurrent sessions across all listeners of a process,
// keeping fd use below LimitNOFILE.
type SessionLimit struct{ ch chan struct{} }

// NewSessionLimit returns a limit of n sessions, or nil (unlimited) for n <= 0.
func NewSessionLimit(n int) *SessionLimit {
	if n <= 0 {
		return nil
	}
	return &SessionLimit{ch: make(chan struct{}, n)}
}

func (s *SessionLimit) tryAcquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *SessionLimit) release() {
	if s != nil {
		<-s.ch
	}
}

func (l *Listener) handle(c net.Conn) {
	start := time.Now()
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	sni, result := "-", "ok"
	l.Stats.begin(l.Proto.Name())
	defer func() {
		c.Close()
		l.Stats.end(l.Proto.Name(), result)
		if (result == "closed before STARTTLS" || result == "ok") && net.ParseIP(ip).IsLoopback() {
			return // watchdog health probe, not worth a log line every few seconds
		}
		l.Log.Printf("%s client=%s sni=%q result=%q duration=%s", l.Proto.Name(), ip, sni, result, time.Since(start).Round(time.Millisecond))
	}()

	if !l.Sessions.tryAcquire() {
		result = "too many connections in total"
		return
	}
	defer l.Sessions.release()

	if !l.acquire(ip) {
		result = "too many connections from this IP"
		return
	}
	defer l.release(ip)

	overall := time.Now().Add(l.PreTLSTimeout)
	_ = c.SetDeadline(overall)
	br := bufio.NewReaderSize(&cmdReader{c: c, per: l.PreTLSCommandTimeout, overall: overall}, 1024)
	if err := l.Proto.Client(br, c, l.Banner); err != nil {
		switch {
		case errors.Is(err, errClose), errors.Is(err, io.EOF):
			// QUIT/LOGOUT, or the peer hung up (health checks do this).
			result = "closed before STARTTLS"
		case errors.Is(err, ErrTLSOnPlainPort):
			result = err.Error()
		default:
			result = "pre-TLS: " + err.Error()
		}
		return
	}

	_ = c.SetDeadline(time.Now().Add(l.HandshakeTimeout))
	ct := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if h.ServerName != "" {
				sni = logSNI(h.ServerName)
			}
			return l.Certs.Get(h)
		},
	})
	if err := ct.Handshake(); err != nil {
		result = "client TLS: " + err.Error()
		return
	}

	up, err := l.dialUpstream(c.RemoteAddr())
	if err != nil {
		result = "upstream dial: " + err.Error()
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(l.HandshakeTimeout))
	ubr := bufio.NewReaderSize(up, 4096)
	if err := l.Proto.Upstream(ubr, up); err != nil {
		result = "upstream: " + err.Error()
		return
	}
	if ubr.Buffered() > 0 {
		result = "upstream sent data after STARTTLS"
		return
	}
	ut := tls.Client(up, l.UpstreamTLS.Clone())
	if err := ut.Handshake(); err != nil {
		result = "upstream TLS: " + err.Error()
		return
	}

	// Both sides are encrypted: forward bytes. No idle deadline by default, so
	// IMAP IDLE lasts as long as client and server keep it; TCP keepalive finds
	// dead peers. IdleTimeout, when set, closes sessions with no traffic.
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	pipe(ct, ut, l.IdleTimeout)
}

// cmdReader gives every read during the pre-TLS phase its own deadline, so a
// client must send each command within per, and never past overall.
type cmdReader struct {
	c       net.Conn
	per     time.Duration
	overall time.Time
}

func (r *cmdReader) Read(p []byte) (int, error) {
	d := r.overall
	if r.per > 0 {
		if t := time.Now().Add(r.per); t.Before(d) {
			d = t
		}
	}
	_ = r.c.SetReadDeadline(d)
	return r.c.Read(p)
}

// activityReader records the time of the last successful read.
type activityReader struct {
	r    io.Reader
	last *atomic.Int64
}

func (a activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func pipe(a, b net.Conn, idle time.Duration) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, activityReader{r: src, last: &last})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	if idle > 0 {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			t := time.NewTicker(idleCheckInterval(idle))
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					if time.Since(time.Unix(0, last.Load())) >= idle {
						a.Close()
						b.Close()
						return
					}
				}
			}
		}()
	}
	<-done
	// Give the other direction a moment to flush, then close both.
	t := time.NewTimer(5 * time.Second)
	select {
	case <-done:
	case <-t.C:
	}
	t.Stop()
	a.Close()
	b.Close()
}

func idleCheckInterval(idle time.Duration) time.Duration {
	iv := idle / 4
	if iv < 10*time.Millisecond {
		iv = 10 * time.Millisecond
	}
	if iv > 5*time.Second {
		iv = 5 * time.Second
	}
	return iv
}

func (l *Listener) dialUpstream(client net.Addr) (net.Conn, error) {
	d, err := l.dialer(client)
	if err != nil {
		return nil, err
	}
	return d.Dial("tcp", l.Upstream)
}

// dialer returns the upstream dialer for a client. Transparent mode uses the
// client IP as source, except for loopback clients: those are dialed plainly
// from the local address that reaches upstream, so a local session is never
// presented to Carbonio as 127.0.0.1 through the gateway (issue #21).
func (l *Listener) dialer(client net.Addr) (*net.Dialer, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}
	if !l.Transparent {
		return d, nil
	}
	ta, ok := client.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected client address %v", client)
	}
	if ta.IP.IsLoopback() {
		return d, nil
	}
	d.LocalAddr = &net.TCPAddr{IP: ta.IP}
	d.Control = transparentControl
	return d, nil
}

// limited reports whether the per-IP cap applies to ip. Loopback sources are
// exempt: they are local processes that can already reach Carbonio directly,
// and the watchdog probes from loopback, so a local process filling a
// loopback bucket must not be able to make the probe fail and force fail-open
// (issue #17). Internet clients keep their real address through the redirect
// and TPROXY, so they never appear as loopback.
func (l *Listener) limited(ip string) bool {
	if l.MaxPerIP <= 0 {
		return false
	}
	p := net.ParseIP(ip)
	return p == nil || !p.IsLoopback()
}

func (l *Listener) acquire(ip string) bool {
	if !l.limited(ip) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP == nil {
		l.perIP = map[string]int{}
	}
	if l.perIP[ip] >= l.MaxPerIP {
		return false
	}
	l.perIP[ip]++
	return true
}

func (l *Listener) release(ip string) {
	if !l.limited(ip) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}
