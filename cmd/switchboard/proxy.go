package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/metrics"
	"github.com/afatyoo/switchboard/internal/starttls"
)

// cmdProxy runs the STARTTLS proxy in the foreground (systemd service).
func cmdProxy(cfg config.Config) error {
	if err := cfg.ValidateProxy(); err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if cfg.Proxy.UpstreamCA != "" {
		pem, err := os.ReadFile(cfg.Proxy.UpstreamCA)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates in %s", cfg.Proxy.UpstreamCA)
		}
	}
	upTLS := &tls.Config{ServerName: cfg.Proxy.UpstreamVerifyName, RootCAs: roots, MinVersion: tls.VersionTLS12}
	certs := &starttls.Certs{Dir: cfg.CertDir, Default: cfg.Proxy.DefaultCert}
	logger := log.New(os.Stdout, "", 0)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(cfg.Proxy.Listeners))
	stats := &starttls.Stats{}
	sessions := starttls.NewSessionLimit(cfg.Proxy.MaxSessions)
	if cfg.Proxy.StatsFile != "" {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				if err := metrics.WriteJSON(cfg.Proxy.StatsFile, stats.Snapshot()); err != nil {
					logger.Printf("stats file: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	for _, lc := range cfg.Proxy.Listeners {
		p, err := starttls.ByName(lc.Protocol)
		if err != nil {
			return err
		}
		l := &starttls.Listener{
			Proto:       p,
			Listen:      lc.Listen,
			Upstream:    lc.Upstream,
			Banner:      cfg.Proxy.Banner,
			Certs:       certs,
			UpstreamTLS: upTLS,
			Transparent: cfg.Proxy.Transparent,
			MaxPerIP:    cfg.Proxy.MaxPerIP,
			Log:         logger,
			Stats:       stats,
			Sessions:    sessions,

			PreTLSCommandTimeout: cfg.Proxy.PreTLSCommandTimeout,
			IdleTimeout:          cfg.Proxy.IdleTimeout,
		}
		go func() { errc <- l.Serve(ctx) }()
	}
	select {
	case <-ctx.Done():
		logger.Println("shutting down")
		return nil
	case err := <-errc:
		return err
	}
}
