// Command switchboard manages per-domain certificates for the Switchboard
// SNI gateway (HAProxy in front of Carbonio Proxy).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/haproxy"
	"github.com/afatyoo/switchboard/internal/store"
)

var version = "dev"

const usage = `Usage: switchboard [-config FILE] COMMAND [ARGS]

Commands:
  add HOSTNAME -cert FILE -key FILE [-chain FILE]   validate and install a certificate
  remove HOSTNAME                                   remove a certificate
  list                                              show installed certificates
  check                                             validate all certificates (exit 1 on problems)
  sync [-dry-run]                                   (mode ldap) install certificates from Carbonio LDAP
  version                                          print the version
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("switchboard", flag.ContinueOnError)
	global.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := global.String("config", "/etc/switchboard/config.yaml", "configuration file")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		global.Usage()
		return errors.New("missing command")
	}
	cmd, rest := rest[0], rest[1:]
	if cmd == "version" {
		fmt.Println(version)
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	roots, err := cfg.Roots()
	if err != nil {
		return err
	}
	st := &store.Store{
		Dir:   cfg.CertDir,
		Group: cfg.Group,
		HAProxy: haproxy.Runner{
			CheckCmd:  cfg.HAProxy.CheckCmd,
			ReloadCmd: cfg.HAProxy.ReloadCmd,
			Timeout:   cfg.HAProxy.Timeout,
		},
	}
	opts := cert.Options{Roots: roots, WarnDays: cfg.WarnDays}

	switch cmd {
	case "add":
		return withLock(cfg.LockFile, func() error {
			if err := cmdAdd(st, opts, rest); err != nil {
				return err
			}
			// A manual add takes the hostname over from sync.
			return forgetManaged(cfg, rest[0])
		})
	case "remove":
		if len(rest) != 1 {
			return errors.New("usage: switchboard remove HOSTNAME")
		}
		return withLock(cfg.LockFile, func() error {
			if err := st.Remove(rest[0]); err != nil {
				return err
			}
			fmt.Printf("removed %s, HAProxy reloaded\n", rest[0])
			return forgetManaged(cfg, rest[0])
		})
	case "sync":
		if cfg.Mode != "ldap" {
			return errors.New("sync needs mode: ldap in the configuration")
		}
		fs := flag.NewFlagSet("sync", flag.ContinueOnError)
		dry := fs.Bool("dry-run", false, "show the plan without changing anything")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return withLock(cfg.LockFile, func() error { return cmdSync(cfg, st, opts, *dry) })
	case "list":
		return cmdList(st, opts, false)
	case "check":
		return cmdList(st, opts, true)
	default:
		global.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdAdd(st *store.Store, opts cert.Options, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: switchboard add HOSTNAME -cert FILE -key FILE [-chain FILE]")
	}
	host := args[0]
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	certFile := fs.String("cert", "", "certificate file (PEM)")
	keyFile := fs.String("key", "", "private key file (PEM, unencrypted)")
	chainFile := fs.String("chain", "", "intermediate chain file (PEM)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" {
		return errors.New("-cert and -key are required")
	}
	b, err := cert.LoadFiles(*certFile, *chainFile, *keyFile)
	if err != nil {
		return err
	}
	r, err := b.Validate(host, opts)
	if err != nil {
		return fmt.Errorf("%s rejected: %w", host, err)
	}
	if err := st.Install(host, b.HAProxyPEM()); err != nil {
		return err
	}
	fmt.Printf("installed %s (issuer %q, expires %s, %d days left), HAProxy reloaded\n",
		host, r.Issuer, r.NotAfter.Format("2006-01-02"), r.DaysLeft)
	for _, w := range r.Warnings {
		fmt.Printf("warning: %s: %s\n", host, w)
	}
	return nil
}

func cmdList(st *store.Store, opts cert.Options, strict bool) error {
	entries, err := st.List()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOSTNAME\tEXPIRES\tDAYS\tISSUER\tSTATUS")
	problems := 0
	for _, e := range entries {
		if e.Err != nil {
			problems++
			fmt.Fprintf(tw, "%s\t-\t-\t-\tunreadable: %v\n", e.Hostname, e.Err)
			continue
		}
		r, err := e.Bundle.Validate(e.Hostname, opts)
		if err != nil {
			problems++
			fmt.Fprintf(tw, "%s\t%s\t-\t%s\tinvalid: %v\n", e.Hostname,
				e.Bundle.Leaf.NotAfter.Format("2006-01-02"), e.Bundle.Leaf.Issuer.CommonName, err)
			continue
		}
		status := "ok"
		if len(r.Warnings) > 0 {
			problems++
			status = "warning: " + r.Warnings[0]
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", e.Hostname, r.NotAfter.Format("2006-01-02"), r.DaysLeft, r.Issuer, status)
	}
	tw.Flush()
	if strict && problems > 0 {
		return fmt.Errorf("%d certificate(s) need attention", problems)
	}
	return nil
}

// withLock serializes changes between manual runs and timers.
func withLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer f.Close()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("another switchboard process holds the lock")
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
