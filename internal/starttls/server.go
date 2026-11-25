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

	PreTLSTimeout    time.Duration
	HandshakeTimeout time.Duration

	mu    sync.Mutex
	perIP map[string]int
}

// Serve accepts connections until ctx is cancelled.
func (l *Listener) Serve(ctx context.Context) error {
	if l.PreTLSTimeout == 0 {
		l.PreTLSTimeout = 60 * time.Second
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
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go l.handle(c)
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
		if result == "closed before STARTTLS" && net.ParseIP(ip).IsLoopback() {
			return // watchdog health probe, not worth a log line every few seconds
		}
		l.Log.Printf("%s client=%s sni=%s result=%q duration=%s", l.Proto.Name(), ip, sni, result, time.Since(start).Round(time.Millisecond))
	}()

	if !l.acquire(ip) {
		result = "too many connections from this IP"
		return
	}
	defer l.release(ip)

	_ = c.SetDeadline(time.Now().Add(l.PreTLSTimeout))
	br := bufio.NewReaderSize(c, 1024)
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
				sni = h.ServerName
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

	// Both sides are encrypted: forward bytes. No idle deadline, so IMAP IDLE
	// lasts as long as client and server keep it; TCP keepalive finds dead peers.
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})
	pipe(ct, ut)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
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

func (l *Listener) dialUpstream(client net.Addr) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 60 * time.Second}
	if l.Transparent {
		ta, ok := client.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("unexpected client address %v", client)
		}
		d.LocalAddr = &net.TCPAddr{IP: ta.IP}
		d.Control = transparentControl
	}
	return d.Dial("tcp", l.Upstream)
}

func (l *Listener) acquire(ip string) bool {
	if l.MaxPerIP <= 0 {
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
	if l.MaxPerIP <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}
