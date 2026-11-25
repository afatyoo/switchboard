package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/store"
	"github.com/afatyoo/switchboard/internal/watchdog"
)

// cmdWatchdog runs the fail-open watchdog in the foreground (systemd service).
// With watchdog.metrics_file set it also writes Prometheus metrics.
func cmdWatchdog(cfg config.Config, st *store.Store, opts cert.Options) error {
	if err := cfg.ValidateWatchdog(); err != nil {
		return err
	}
	var ports []watchdog.Port
	for _, p := range cfg.Watchdog.Ports {
		ports = append(ports, watchdog.Port{Public: p.Public, Local: p.Local, Check: p.Check})
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := log.New(os.Stdout, "", 0)
	w := &watchdog.Watchdog{
		Ports:        ports,
		Firewall:     watchdog.IPTables{},
		Probe:        (&watchdog.Checker{DeepEvery: cfg.Watchdog.DeepEvery}).Probe,
		Interval:     cfg.Watchdog.Interval,
		FailAfter:    cfg.Watchdog.FailAfter,
		RecoverAfter: cfg.Watchdog.RecoverAfter,
		Log:          logger,
	}
	if cfg.Watchdog.MetricsFile != "" {
		e := &exporter{cfg: cfg, st: st, opts: opts, log: logger, certEvery: 5 * time.Minute}
		w.AfterTick = e.afterTick
		logger.Printf("watchdog: writing metrics to %s", cfg.Watchdog.MetricsFile)
	}
	logger.Printf("watchdog: watching %d port(s) every %s", len(ports), cfg.Watchdog.Interval)
	return w.Run(ctx)
}
