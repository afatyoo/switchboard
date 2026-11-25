package watchdog

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afatyoo/switchboard/internal/starttls"
	"github.com/afatyoo/switchboard/internal/testpki"
)

// fakeCarbonio speaks the plain part of proto, accepts STARTTLS and then
// answers EHLO / NOOP / CAPA like the real servers.
func fakeCarbonio(t *testing.T, proto string, cert tls.Certificate) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				read := func() string { l, _ := r.ReadString('\n'); return strings.TrimSpace(l) }
				switch proto {
				case "smtp":
					io.WriteString(c, "220 carbonio ESMTP\r\n")
					read()
					io.WriteString(c, "250-carbonio\r\n250 STARTTLS\r\n")
					read()
					io.WriteString(c, "220 go\r\n")
				case "imap":
					io.WriteString(c, "* OK carbonio\r\n")
					tag := strings.Fields(read())[0]
					io.WriteString(c, tag+" OK begin\r\n")
				case "pop3":
					io.WriteString(c, "+OK carbonio\r\n")
					read()
					io.WriteString(c, "+OK begin\r\n")
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				tr := bufio.NewReader(tc)
				for {
					l, err := tr.ReadString('\n')
					if err != nil {
						return
					}
					f := strings.Fields(l)
					switch {
					case len(f) > 0 && strings.EqualFold(f[0], "EHLO"):
						io.WriteString(tc, "250-carbonio\r\n250 AUTH PLAIN\r\n")
					case len(f) > 1 && strings.EqualFold(f[1], "NOOP"):
						io.WriteString(tc, f[0]+" OK NOOP completed\r\n")
					case len(f) > 0 && strings.EqualFold(f[0], "CAPA"):
						io.WriteString(tc, "+OK\r\nUSER\r\n.\r\n")
					default:
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func startProxy(t *testing.T, proto, upstream string, ca *testpki.CA) int {
	t.Helper()
	dir := t.TempDir()
	c, k := ca.ValidLeaf("mail.provider.test")
	def := filepath.Join(dir, "default.pem")
	os.WriteFile(def, append(c, k...), 0o600)
	p, _ := starttls.ByName(proto)
	l := &starttls.Listener{
		Proto: p, Upstream: upstream, Banner: "mail.provider.test",
		Certs:       &starttls.Certs{Dir: dir, Default: def},
		UpstreamTLS: &tls.Config{ServerName: "carbonio.test", RootCAs: ca.Pool()},
		Log:         log.New(io.Discard, "", 0),
		Listen:      "127.0.0.1:0",
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // reuse the free port number
	l.Listen = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go l.Serve(ctx)
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", l.Listen); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ln.Addr().(*net.TCPAddr).Port
}

func TestStartTLSProbeReachesCarbonio(t *testing.T) {
	ca := testpki.NewCA(true)
	uc, uk := ca.ValidLeaf("carbonio.test")
	upCert, _ := tls.X509KeyPair(uc, uk)
	for _, proto := range []string{"smtp", "imap", "pop3"} {
		t.Run(proto, func(t *testing.T) {
			up := fakeCarbonio(t, proto, upCert)
			port := startProxy(t, proto, up.Addr().String(), ca)
			p := Port{Public: 1, Local: port, Check: "starttls"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := DefaultProbe(ctx, p); err != nil {
				t.Fatalf("healthy path reported down: %v", err)
			}

			// Carbonio goes away: the proxy still greets, the full probe must fail.
			up.Close()
			if err := probeGreeting(ctx, p); err != nil {
				t.Fatalf("greeting check should still pass: %v", err)
			}
			if err := DefaultProbe(ctx, p); err == nil {
				t.Fatal("full probe passed with Carbonio down")
			}
		})
	}
}

func TestCheckerRunsFullProbeOnlyEveryDeepEvery(t *testing.T) {
	ca := testpki.NewCA(true)
	uc, uk := ca.ValidLeaf("carbonio.test")
	upCert, _ := tls.X509KeyPair(uc, uk)
	up := fakeCarbonio(t, "imap", upCert)
	port := startProxy(t, "imap", up.Addr().String(), ca)
	p := Port{Public: 143, Local: port, Check: "starttls"}
	ctx := context.Background()

	ck := &Checker{DeepEvery: time.Hour}
	if err := ck.Probe(ctx, p); err != nil {
		t.Fatal(err)
	}
	up.Close()
	// Within DeepEvery only the greeting is checked, so this still passes.
	if err := ck.Probe(ctx, p); err != nil {
		t.Fatalf("cached full check not used: %v", err)
	}
	// Forcing a new full check detects the outage.
	ck.mu.Lock()
	delete(ck.lastDeep, 143)
	ck.mu.Unlock()
	if err := ck.Probe(ctx, p); err == nil {
		t.Fatal("full probe passed with Carbonio down")
	}
	// After a failure the full check runs every time until it passes.
	if err := ck.Probe(ctx, p); err == nil {
		t.Fatal("failed full check was cached")
	}
}
