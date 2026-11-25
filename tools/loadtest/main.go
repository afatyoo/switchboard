// Command loadtest opens many IMAP sessions through Switchboard and keeps them
// alive, to measure how the gateway behaves with long-lived connections.
//
//	loadtest -host 192.0.2.10 -mode imaps -n 1000 -sni mail.customer1.test -hold 3m
//	loadtest -host 192.0.2.10 -mode starttls -n 150 -login user@example.com -passfile pw -idle
//
// Without -login the sessions stay unauthenticated and send CAPABILITY every
// -keepalive. With -login and -idle they authenticate and sit in IDLE.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	host      = flag.String("host", "", "server address")
	mode      = flag.String("mode", "imaps", "imaps (993) or starttls (143)")
	n         = flag.Int("n", 100, "sessions")
	rate      = flag.Int("rate", 50, "new sessions per second")
	sni       = flag.String("sni", "mail.customer1.test", "SNI name")
	hold      = flag.Duration("hold", 3*time.Minute, "how long to keep sessions open after ramp up")
	keepalive = flag.Duration("keepalive", 30*time.Second, "CAPABILITY interval for unauthenticated sessions")
	login     = flag.String("login", "", "account to log in with")
	passfile  = flag.String("passfile", "", "file with the password (password=... or plain)")
	idle      = flag.Bool("idle", false, "enter IDLE after login")
	insecure  = flag.Bool("insecure", true, "skip certificate verification (load test only)")
)

type counters struct {
	connected, failed, alive, dropped atomic.Int64
	errs                              sync.Map
}

func (c *counters) fail(stage string, err error) {
	c.failed.Add(1)
	key := stage + ": " + shortErr(err)
	v, _ := c.errs.LoadOrStore(key, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 && len(s)-i < 60 {
		return s[i+2:]
	}
	if len(s) > 80 {
		return s[:80]
	}
	return s
}

func main() {
	flag.Parse()
	if *host == "" {
		log.Fatal("-host is required")
	}
	password := ""
	if *login != "" {
		b, err := os.ReadFile(*passfile)
		if err != nil {
			log.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "password=") {
				password = strings.TrimPrefix(l, "password=")
			}
		}
		if password == "" {
			password = strings.TrimSpace(string(b))
		}
	}
	tlsCfg := &tls.Config{ServerName: *sni, InsecureSkipVerify: *insecure}

	var c counters
	stop := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	tick := time.NewTicker(time.Second / time.Duration(*rate))
	for i := 0; i < *n; i++ {
		<-tick.C
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			session(id, tlsCfg, password, &c, stop)
		}(i)
	}
	tick.Stop()
	ramp := time.Since(start)
	report := func(label string) {
		fmt.Printf("%-10s connected=%d alive=%d failed=%d dropped=%d\n", label,
			c.connected.Load(), c.alive.Load(), c.failed.Load(), c.dropped.Load())
	}
	time.Sleep(5 * time.Second)
	report(fmt.Sprintf("ramp %s", ramp.Round(time.Second)))
	end := time.After(*hold)
	t := time.NewTicker(30 * time.Second)
loop:
	for {
		select {
		case <-t.C:
			report("holding")
		case <-end:
			break loop
		}
	}
	report("final")
	c.errs.Range(func(k, v any) bool {
		fmt.Printf("  error x%d  %s\n", v.(*atomic.Int64).Load(), k)
		return true
	})
	close(stop)
	wg.Wait()
}

func session(id int, tlsCfg *tls.Config, password string, c *counters, stop chan struct{}) {
	var conn net.Conn
	var err error
	addr := net.JoinHostPort(*host, "993")
	if *mode == "starttls" {
		addr = net.JoinHostPort(*host, "143")
	}
	raw, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		c.fail("dial", err)
		return
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	if *mode == "starttls" {
		r := bufio.NewReader(raw)
		if _, err := r.ReadString('\n'); err != nil {
			c.fail("greeting", err)
			return
		}
		fmt.Fprintf(raw, "s STARTTLS\r\n")
		l, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(l, "s OK") {
			c.fail("starttls", fmt.Errorf("%q %v", strings.TrimSpace(l), err))
			return
		}
	}
	tc := tls.Client(raw, tlsCfg)
	if err := tc.Handshake(); err != nil {
		c.fail("tls", err)
		return
	}
	conn = tc
	r := bufio.NewReader(conn)
	if *mode == "imaps" {
		if _, err := r.ReadString('\n'); err != nil {
			c.fail("greeting", err)
			return
		}
	}
	// One round trip proves the upstream leg works too.
	if err := cmd(conn, r, "c0 CAPABILITY", "c0 "); err != nil {
		c.fail("capability", err)
		return
	}
	if *login != "" {
		if err := cmd(conn, r, fmt.Sprintf("l LOGIN %s %s", *login, password), "l "); err != nil {
			c.fail("login", err)
			return
		}
		if err := cmd(conn, r, "s SELECT INBOX", "s "); err != nil {
			c.fail("select", err)
			return
		}
	}
	c.connected.Add(1)
	c.alive.Add(1)
	defer c.alive.Add(-1)
	_ = raw.SetDeadline(time.Time{})

	if *idle && *login != "" {
		fmt.Fprintf(conn, "i IDLE\r\n")
		if l, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(l, "+") {
			c.fail("idle", fmt.Errorf("%q %v", strings.TrimSpace(l), err))
			return
		}
		done := make(chan error, 1)
		go func() {
			for {
				if _, err := r.ReadString('\n'); err != nil {
					done <- err
					return
				}
			}
		}()
		select {
		case <-stop:
			fmt.Fprintf(conn, "DONE\r\n")
		case err := <-done:
			c.dropped.Add(1)
			c.fail("dropped", err)
		}
		return
	}

	t := time.NewTicker(*keepalive)
	defer t.Stop()
	for k := 1; ; k++ {
		select {
		case <-stop:
			fmt.Fprintf(conn, "z LOGOUT\r\n")
			return
		case <-t.C:
			_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
			if err := cmd(conn, r, fmt.Sprintf("k%d CAPABILITY", k), fmt.Sprintf("k%d ", k)); err != nil {
				c.dropped.Add(1)
				c.fail("keepalive", err)
				return
			}
			_ = raw.SetDeadline(time.Time{})
		}
	}
}

// cmd sends a command and reads until the tagged reply.
func cmd(w net.Conn, r *bufio.Reader, line, tag string) error {
	if _, err := fmt.Fprintf(w, "%s\r\n", line); err != nil {
		return err
	}
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, tag) {
			if strings.HasPrefix(l[len(tag):], "OK") {
				return nil
			}
			return fmt.Errorf("%s", strings.TrimSpace(l))
		}
	}
}
