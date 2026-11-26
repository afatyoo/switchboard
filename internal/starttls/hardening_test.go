package starttls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func certNames(t *testing.T, der []byte) string {
	t.Helper()
	x, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName + " " + strings.Join(x.DNSNames, ",")
}

// Issue #19: invalid names fall back to the default certificate, valid names
// still select their file.
func TestCertsGetValidatesName(t *testing.T) {
	p := newPKI(t)
	c := &Certs{Dir: p.dir, Default: p.defPath}
	cases := map[string]string{
		"mail.customer1.test":                "mail.customer1.test",
		"MAIL.Customer1.test.":               "mail.customer1.test",
		"imap.customer2.test":                "*.customer2.test",
		"mail.customer1.test\nresult=\"ok\"": "mail.provider.test",
		"../mail.customer1.test":             "mail.provider.test",
		"*.customer2.test":                   "mail.provider.test",
		"":                                   "mail.provider.test",
	}
	for sni, want := range cases {
		crt, err := c.Get(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("%q: %v", sni, err)
		}
		if got := certNames(t, crt.Certificate[0]); !strings.Contains(got, want) {
			t.Errorf("%q selected %q, want %q", sni, got, want)
		}
	}
}

func TestLogSNI(t *testing.T) {
	for in, want := range map[string]string{
		"":                          "-",
		"Mail.Example.test.":        "mail.example.test",
		"a b":                       "invalid",
		"x.test\nfoo result=\"ok\"": "invalid",
	} {
		if got := logSNI(in); got != want {
			t.Errorf("logSNI(%q) = %q, want %q", in, got, want)
		}
	}
}

// Issue #19: a ClientHello with a newline in server_name yields exactly one
// log line and the default certificate.
func TestSNINewlineLogsOneLine(t *testing.T) {
	p := newPKI(t)
	pr, _ := ByName("smtp")
	logs := &syncBuffer{}
	l := &Listener{
		Proto:  pr,
		Banner: "mail.provider.test",
		Certs:  &Certs{Dir: p.dir, Default: p.defPath},
		// Unreachable upstream: the session ends after the client handshake.
		Upstream:         "127.0.0.1:1",
		UpstreamTLS:      &tls.Config{},
		Log:              log.New(logs, "", 0),
		PreTLSTimeout:    5 * time.Second,
		HandshakeTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.serve(ctx, ln)

	// The Go client sends ServerName as is, newline included.
	tc := clientStartTLSConfig(t, "smtp", ln.Addr().String(), &tls.Config{
		ServerName:         "mail.customer1.test\nsmtp client=1.2.3.4 sni=x result=\"ok\"",
		InsecureSkipVerify: true,
	})
	got := certNames(t, tc.ConnectionState().PeerCertificates[0].Raw)
	tc.Close()
	if !strings.Contains(got, "mail.provider.test") {
		t.Fatalf("certificate %q, want default", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "result=") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var lines []string
	for _, s := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if !strings.Contains(s, "listening on") {
			lines = append(lines, s)
		}
	}
	if len(lines) != 1 || !strings.Contains(lines[0], `sni="invalid"`) {
		t.Fatalf("log lines %q", lines)
	}
}

// fakeListener fails Accept with EMFILE once, then hands out real conns.
type fakeListener struct {
	net.Listener
	mu     sync.Mutex
	failed bool
}

func (f *fakeListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	if !f.failed {
		f.failed = true
		f.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	f.mu.Unlock()
	return f.Listener.Accept()
}

// Issue #18: EMFILE must not stop the listener.
func TestAcceptEMFILEKeepsServing(t *testing.T) {
	p := newPKI(t)
	up := fakeUpstream(t, "smtp", p.upstream)
	pr, _ := ByName("smtp")
	l := &Listener{
		Proto:            pr,
		Upstream:         up,
		Banner:           "mail.provider.test",
		Certs:            &Certs{Dir: p.dir, Default: p.defPath},
		UpstreamTLS:      &tls.Config{ServerName: "upstream.test", RootCAs: p.ca.Pool()},
		Log:              log.New(io.Discard, "", 0),
		PreTLSTimeout:    5 * time.Second,
		HandshakeTimeout: 5 * time.Second,
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- l.serve(ctx, &fakeListener{Listener: inner}) }()

	tc := clientStartTLS(t, "smtp", inner.Addr().String(), "mail.customer1.test", p.ca.Pool())
	io.WriteString(tc, "NOOP\r\n")
	buf := make([]byte, 64)
	n, _ := tc.Read(buf)
	tc.Close()
	if !strings.HasPrefix(string(buf[:n]), "got NOOP") {
		t.Fatalf("after EMFILE got %q", buf[:n])
	}
	select {
	case err := <-errc:
		t.Fatalf("serve returned early: %v", err)
	default:
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("serve after cancel: %v", err)
	}
}

func TestTransientAcceptErr(t *testing.T) {
	if transientAcceptErr(net.ErrClosed) {
		t.Error("closed listener treated as transient")
	}
	for _, e := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED} {
		if !transientAcceptErr(&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", e)}) {
			t.Errorf("%v not transient", e)
		}
	}
}

// Issue #18: the global limit is shared by listeners and rejects the extra
// session, counted as limited.
func TestGlobalSessionLimit(t *testing.T) {
	if NewSessionLimit(0) != nil {
		t.Fatal("0 must mean unlimited")
	}
	pr, _ := ByName("smtp")
	stats := &Stats{}
	lim := NewSessionLimit(1)
	mk := func() *Listener {
		return &Listener{Proto: pr, Banner: "mail.provider.test", Sessions: lim, Stats: stats,
			Log: log.New(io.Discard, "", 0), PreTLSTimeout: 5 * time.Second, HandshakeTimeout: 5 * time.Second}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var addrs []string
	for _, l := range []*Listener{mk(), mk()} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, ln.Addr().String())
		go l.serve(ctx, ln)
	}
	// The first session holds the only slot in the plain text phase.
	c1, err := net.Dial("tcp", addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c1.Read(make([]byte, 128)); err != nil {
		t.Fatalf("first session banner: %v", err)
	}
	// The second, on the other listener, is closed without a banner.
	c2, err := net.Dial("tcp", addrs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := c2.Read(make([]byte, 128)); err == nil {
		t.Fatalf("extra session got %d bytes", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for stats.Snapshot().Connections["smtp"]["limited"] != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := stats.Snapshot().Connections["smtp"]["limited"]; got != 1 {
		t.Fatalf("limited = %d", got)
	}
}

// Issue #18: IdleTimeout closes a piped session with no traffic.
func TestIdleTimeoutClosesPipe(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { pipe(a2, b1, 100*time.Millisecond); close(done) }()
	go func() { a1.Write([]byte("x")) }()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle session not closed")
	}
	_ = a1.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a1.Read(buf); err == nil {
		t.Fatal("client side still open")
	}
}

// Without IdleTimeout a quiet session stays open (IMAP IDLE).
func TestNoIdleTimeoutByDefault(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	done := make(chan struct{})
	go func() { pipe(a2, b1, 0); close(done) }()
	select {
	case <-done:
		t.Fatal("session closed without idle timeout")
	case <-time.After(300 * time.Millisecond):
	}
	a1.Close()
	b2.Close()
	<-done
}

// Issue #21: a client silent between commands is dropped after the per
// command timeout, well before the overall pre-TLS deadline.
func TestPreTLSCommandTimeout(t *testing.T) {
	pr, _ := ByName("smtp")
	l := &Listener{Proto: pr, Banner: "mail.provider.test", Log: log.New(io.Discard, "", 0),
		PreTLSTimeout: 10 * time.Second, PreTLSCommandTimeout: 200 * time.Millisecond, HandshakeTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.serve(ctx, ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("read: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("closed after %s", d)
	}
}

// Issue #21: loopback clients are dialed without IP_TRANSPARENT.
func TestDialerLoopbackNotTransparent(t *testing.T) {
	l := &Listener{Transparent: true}
	d, err := l.dialer(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if d.LocalAddr != nil || d.Control != nil {
		t.Fatal("loopback client dialed transparently")
	}
	d, err = l.dialer(&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4000})
	if err != nil {
		t.Fatal(err)
	}
	if d.Control == nil || d.LocalAddr.(*net.TCPAddr).IP.String() != "192.0.2.7" {
		t.Fatal("public client not dialed transparently")
	}
	l.Transparent = false
	if d, _ = l.dialer(&net.TCPAddr{IP: net.ParseIP("192.0.2.7")}); d.Control != nil {
		t.Fatal("non-transparent listener used IP_TRANSPARENT")
	}
}
