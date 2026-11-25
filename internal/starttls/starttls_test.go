package starttls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afatyoo/switchboard/internal/testpki"
)

type pki struct {
	ca       *testpki.CA
	dir      string
	defPath  string
	upstream tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	ca := testpki.NewCA(true)
	dir := t.TempDir()
	write := func(path string, names ...string) {
		c, k := ca.ValidLeaf(names...)
		if err := os.WriteFile(path, append(append(c, ca.PEM...), k...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "mail.customer1.test.pem"), "mail.customer1.test")
	write(filepath.Join(dir, "_wildcard.customer2.test.pem"), "*.customer2.test")
	def := filepath.Join(t.TempDir(), "default.pem")
	write(def, "mail.provider.test")
	uc, uk := ca.ValidLeaf("upstream.test")
	up, err := tls.X509KeyPair(uc, uk)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{ca: ca, dir: dir, defPath: def, upstream: up}
}

// fakeUpstream speaks the plain text part of proto, accepts STARTTLS, then
// answers every line with "got <line>".
func fakeUpstream(t *testing.T, proto string, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				say := func(s string) { io.WriteString(c, s) }
				read := func() string { l, _ := r.ReadString('\n'); return strings.TrimSpace(l) }
				switch proto {
				case "smtp":
					say("220 upstream ESMTP\r\n")
					read() // EHLO
					say("250-upstream\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
					read() // STARTTLS
					say("220 go ahead\r\n")
				case "imap":
					say("* OK upstream ready\r\n")
					tag := strings.Fields(read())[0]
					say(tag + " OK Begin TLS\r\n")
				case "pop3":
					say("+OK upstream ready\r\n")
					read()
					say("+OK begin\r\n")
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				tr := bufio.NewReader(tc)
				for {
					l, err := tr.ReadString('\n')
					if err != nil {
						return
					}
					io.WriteString(tc, "got "+strings.TrimSpace(l)+"\r\n")
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startProxy(t *testing.T, proto string, p *pki, upstream string) string {
	t.Helper()
	pr, err := ByName(proto)
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{
		Proto:       pr,
		Upstream:    upstream,
		Banner:      "mail.provider.test",
		Certs:       &Certs{Dir: p.dir, Default: p.defPath},
		UpstreamTLS: &tls.Config{ServerName: "upstream.test", RootCAs: p.ca.Pool()},
		MaxPerIP:    5,
		Log:         log.New(io.Discard, "", 0),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l.PreTLSTimeout, l.HandshakeTimeout = 5*time.Second, 5*time.Second
	go l.serve(ctx, ln)
	return ln.Addr().String()
}

// clientStartTLS runs the client side up to STARTTLS and returns the TLS conn.
func clientStartTLS(t *testing.T, proto, addr, sni string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	read := func() string { l, _ := r.ReadString('\n'); return strings.TrimSpace(l) }
	say := func(s string) { io.WriteString(c, s) }
	switch proto {
	case "smtp":
		read()
		say("EHLO client\r\n")
		for l := read(); !strings.HasPrefix(l, "250 "); l = read() {
		}
		say("MAIL FROM:<x@y>\r\n")
		if l := read(); !strings.HasPrefix(l, "530") {
			t.Fatalf("MAIL before STARTTLS answered %q", l)
		}
		say("STARTTLS\r\n")
		if l := read(); !strings.HasPrefix(l, "220") {
			t.Fatalf("STARTTLS answered %q", l)
		}
	case "imap":
		read()
		say("a1 LOGIN u p\r\n")
		if l := read(); !strings.Contains(l, "NO") {
			t.Fatalf("LOGIN before STARTTLS answered %q", l)
		}
		say("a2 STARTTLS\r\n")
		if l := read(); !strings.HasPrefix(l, "a2 OK") {
			t.Fatalf("STARTTLS answered %q", l)
		}
	case "pop3":
		read()
		say("USER u\r\n")
		if l := read(); !strings.HasPrefix(l, "-ERR") {
			t.Fatalf("USER before STLS answered %q", l)
		}
		say("STLS\r\n")
		if l := read(); !strings.HasPrefix(l, "+OK") {
			t.Fatalf("STLS answered %q", l)
		}
	}
	tc := tls.Client(c, &tls.Config{ServerName: sni, RootCAs: roots})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tc
}

func TestProtocols(t *testing.T) {
	p := newPKI(t)
	for _, proto := range []string{"smtp", "imap", "pop3"} {
		t.Run(proto, func(t *testing.T) {
			addr := startProxy(t, proto, p, fakeUpstream(t, proto, p.upstream))
			for sni, wantCN := range map[string]string{
				"mail.customer1.test": "mail.customer1.test",
				"imap.customer2.test": "*.customer2.test",
				"mail.provider.test":  "mail.provider.test", // default
			} {
				tc := clientStartTLS(t, proto, addr, sni, p.ca.Pool())
				if cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != wantCN {
					t.Errorf("sni %s: got cert %s, want %s", sni, cn, wantCN)
				}
				io.WriteString(tc, "HELLO\r\n")
				l, _ := bufio.NewReader(tc).ReadString('\n')
				if strings.TrimSpace(l) != "got HELLO" {
					t.Errorf("sni %s: upstream echo %q", sni, l)
				}
				tc.Close()
			}
		})
	}
}

func TestStartTLSInjectionRejected(t *testing.T) {
	p := newPKI(t)
	addr := startProxy(t, "smtp", p, fakeUpstream(t, "smtp", p.upstream))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	r.ReadString('\n')
	io.WriteString(c, "EHLO x\r\n")
	for l, _ := r.ReadString('\n'); !strings.HasPrefix(l, "250 "); l, _ = r.ReadString('\n') {
	}
	io.WriteString(c, "STARTTLS\r\nMAIL FROM:<evil@x>\r\n")
	if l, err := r.ReadString('\n'); err == nil && strings.HasPrefix(l, "220") {
		t.Fatalf("proxy accepted STARTTLS with injected data: %q", l)
	}
}

func TestLongLineAndCommandLimit(t *testing.T) {
	p := newPKI(t)
	addr := startProxy(t, "pop3", p, fakeUpstream(t, "pop3", p.upstream))
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	r.ReadString('\n')
	io.WriteString(c, strings.Repeat("A", 2000)+"\r\n")
	// The proxy drops the connection (close or reset) without answering.
	if rest, err := io.ReadAll(r); len(rest) != 0 {
		t.Fatalf("long line answered: %q (%v)", rest, err)
	}

	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	r2 := bufio.NewReader(c2)
	r2.ReadString('\n')
	for i := 0; i < maxCommands+1; i++ {
		io.WriteString(c2, "NOOP\r\n")
	}
	rest, _ := io.ReadAll(r2)
	if !strings.Contains(string(rest), "Too many commands") {
		t.Fatalf("no command limit: %q", rest)
	}
}

func TestImplicitTLSOnStartTLSPortClosesFast(t *testing.T) {
	p := newPKI(t)
	for _, proto := range []string{"smtp", "imap", "pop3"} {
		addr := startProxy(t, proto, p, fakeUpstream(t, proto, p.upstream))
		start := time.Now()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		// A client set to "SSL/TLS" sends a ClientHello right away.
		tc := tls.Client(c, &tls.Config{ServerName: "mail.customer1.test", RootCAs: p.ca.Pool()})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.Handshake(); err == nil {
			t.Fatalf("%s: handshake succeeded on a STARTTLS port", proto)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("%s: client waited %s, want a fast close", proto, d)
		}
		c.Close()
	}
	if _, err := readLine(bufio.NewReader(strings.NewReader("\x16\x03\x01\x02\x00"))); err != ErrTLSOnPlainPort {
		t.Fatalf("readLine: %v", err)
	}
}

func TestStatsCategories(t *testing.T) {
	s := &Stats{}
	for _, r := range []string{"ok", "ok", ErrTLSOnPlainPort.Error(), "upstream TLS: x", "pre-TLS: EOF", "too many connections from this IP"} {
		s.begin("smtp")
		s.end("smtp", r)
	}
	snap := s.Snapshot()
	want := map[string]int64{"ok": 2, "tls_on_plain_port": 1, "upstream_error": 1, "pretls_error": 1, "limited": 1}
	for k, v := range want {
		if snap.Connections["smtp"][k] != v {
			t.Errorf("%s = %d, want %d", k, snap.Connections["smtp"][k], v)
		}
	}
	if snap.Active["smtp"] != 0 {
		t.Errorf("active = %d", snap.Active["smtp"])
	}
}

func TestPerIPLimit(t *testing.T) {
	l := &Listener{MaxPerIP: 2}
	if !l.acquire("1.2.3.4") || !l.acquire("1.2.3.4") || l.acquire("1.2.3.4") {
		t.Fatal("limit not enforced")
	}
	l.release("1.2.3.4")
	if !l.acquire("1.2.3.4") {
		t.Fatal("release did not free a slot")
	}
}
