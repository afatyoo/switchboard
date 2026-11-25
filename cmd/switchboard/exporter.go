package main

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/metrics"
	"github.com/afatyoo/switchboard/internal/store"
	"github.com/afatyoo/switchboard/internal/watchdog"
)

// exporter writes switchboard.prom for the node_exporter textfile collector.
// Certificates are re-validated at most every certEvery.
type exporter struct {
	cfg       config.Config
	st        *store.Store
	opts      cert.Options
	log       *log.Logger
	certEvery time.Duration

	certAt    time.Time
	certCache []certMetric
}

type certMetric struct {
	host    string
	expires time.Time
	valid   bool
}

func (e *exporter) afterTick(w *watchdog.Watchdog) {
	var b metrics.Builder
	w.Collect(&b)
	e.certs(&b)
	e.sync(&b)
	e.proxy(&b)
	if err := metrics.WriteFile(e.cfg.Watchdog.MetricsFile, b.Bytes()); err != nil {
		e.log.Printf("metrics: %v", err)
	}
}

func (e *exporter) certs(b *metrics.Builder) {
	if time.Since(e.certAt) > e.certEvery || e.certCache == nil {
		e.certAt = time.Now()
		e.certCache = e.certCache[:0]
		entries, err := e.st.List()
		if err != nil {
			e.log.Printf("metrics: list certificates: %v", err)
		}
		for _, en := range entries {
			m := certMetric{host: en.Hostname}
			if en.Err == nil {
				m.expires = en.Bundle.Leaf.NotAfter
				_, verr := en.Bundle.Validate(en.Hostname, cert.Options{Roots: e.opts.Roots})
				m.valid = verr == nil
			}
			e.certCache = append(e.certCache, m)
		}
	}
	b.Gauge("switchboard_certificates", "Certificates installed in the Switchboard certificate directory.", nil, float64(len(e.certCache)))
	for _, m := range e.certCache {
		l := metrics.Labels{"hostname": m.host}
		v := 0.0
		if m.valid {
			v = 1
		}
		b.Gauge("switchboard_certificate_valid", "1 if the certificate parses, matches its key, covers the hostname and its chain verifies.", l, v)
		if !m.expires.IsZero() {
			b.Gauge("switchboard_certificate_expiry_timestamp_seconds", "Certificate notAfter as Unix time.", l, float64(m.expires.Unix()))
		}
	}
}

func (e *exporter) sync(b *metrics.Builder) {
	if e.cfg.Mode != "ldap" || e.cfg.LDAP.StatusFile == "" {
		return
	}
	var s metrics.SyncStatus
	if err := metrics.ReadJSON(e.cfg.LDAP.StatusFile, &s); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			e.log.Printf("metrics: sync status: %v", err)
		}
		return
	}
	ok := 0.0
	if s.OK {
		ok = 1
	}
	b.Gauge("switchboard_sync_last_run_timestamp_seconds", "Unix time of the last LDAP sync run.", nil, float64(s.Time))
	b.Gauge("switchboard_sync_last_run_success", "1 if the last LDAP sync succeeded.", nil, ok)
	b.Gauge("switchboard_sync_domains", "Domains with virtual hostnames and a certificate seen by the last sync.", nil, float64(s.Domains))
	b.Gauge("switchboard_sync_skipped", "Virtual hostnames skipped by the last sync (invalid or not covered).", nil, float64(s.Skipped))
}

func (e *exporter) proxy(b *metrics.Builder) {
	if e.cfg.Proxy.StatsFile == "" || len(e.cfg.Proxy.Listeners) == 0 {
		return
	}
	var s metrics.ProxyStats
	if err := metrics.ReadJSON(e.cfg.Proxy.StatsFile, &s); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			e.log.Printf("metrics: proxy stats: %v", err)
		}
		return
	}
	b.Gauge("switchboard_proxy_stats_timestamp_seconds", "Unix time the STARTTLS proxy last wrote its statistics.", nil, float64(s.Time))
	for proto, m := range s.Connections {
		for result, n := range m {
			b.Counter("switchboard_proxy_sessions_total", "STARTTLS proxy sessions by protocol and outcome since the proxy started.", metrics.Labels{"protocol": proto, "result": result}, float64(n))
		}
	}
	for proto, n := range s.Active {
		b.Gauge("switchboard_proxy_sessions_active", "Open STARTTLS proxy sessions.", metrics.Labels{"protocol": proto}, float64(n))
	}
}
