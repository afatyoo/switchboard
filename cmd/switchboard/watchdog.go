package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/watchdog"
)

// cmdWatchdog runs the fail-open watchdog in the foreground (systemd service).
func cmdWatchdog(cfg config.Config) error {
	if err := cfg.ValidateWatchdog(); err != nil {
		return err
	}
	var ports []watchdog.Port
	for _, p := range cfg.Watchdog.Ports {
		ports = append(ports, watchdog.Port{Public: p.Public, Local: p.Local, Check: p.Check})
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	w := &watchdog.Watchdog{
		Ports:        ports,
		Firewall:     watchdog.IPTables{},
		Probe:        watchdog.DefaultProbe,
		Interval:     cfg.Watchdog.Interval,
		FailAfter:    cfg.Watchdog.FailAfter,
		RecoverAfter: cfg.Watchdog.RecoverAfter,
		Log:          log.New(os.Stdout, "", 0),
	}
	w.Log.Printf("watchdog: watching %d port(s) every %s", len(ports), cfg.Watchdog.Interval)
	return w.Run(ctx)
}
