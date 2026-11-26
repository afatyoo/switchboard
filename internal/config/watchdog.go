package config

import (
	"errors"
	"fmt"
	"time"
)

// Watchdog configures `switchboard watchdog`.
type Watchdog struct {
	Interval     time.Duration `yaml:"interval"`
	FailAfter    int           `yaml:"fail_after"`
	RecoverAfter int           `yaml:"recover_after"`
	// MinFailOpenInterval holds back restoring a port's redirect until this
	// long after its last fail-open, to stop flapping. Fail-open itself is
	// never delayed. 0 disables it.
	MinFailOpenInterval time.Duration `yaml:"min_failopen_interval"`
	// DeepEvery is how often the full STARTTLS check (through to Carbonio)
	// runs per port; in between only the proxy greeting is checked.
	DeepEvery time.Duration  `yaml:"deep_every"`
	Ports     []WatchdogPort `yaml:"ports"`
	// MetricsFile is a node_exporter textfile collector file (*.prom).
	// Empty disables metrics.
	MetricsFile string `yaml:"metrics_file"`
}

// WatchdogPort maps a public port to its Switchboard listener.
type WatchdogPort struct {
	Public int    `yaml:"public"`
	Local  int    `yaml:"local"`
	Check  string `yaml:"check"` // tls | starttls ("banner" is the old name for starttls)
}

// DefaultWatchdogPorts matches deploy/iptables/redirect.sh.
func DefaultWatchdogPorts() []WatchdogPort {
	return []WatchdogPort{
		{993, 10993, "tls"}, {995, 10995, "tls"}, {465, 10465, "tls"},
		{587, 10587, "starttls"}, {143, 10143, "starttls"}, {110, 10110, "starttls"},
	}
}

// ValidateWatchdog checks the watchdog section.
func (c Config) ValidateWatchdog() error {
	if len(c.Watchdog.Ports) == 0 {
		return errors.New("watchdog.ports is empty")
	}
	if c.Watchdog.MinFailOpenInterval < 0 {
		return errors.New("watchdog.min_failopen_interval must not be negative")
	}
	if m := c.Watchdog.MinFailOpenInterval; m > 0 && m > 24*time.Hour {
		return fmt.Errorf("watchdog.min_failopen_interval %s is too long (max 24h)", m)
	}
	for i, p := range c.Watchdog.Ports {
		if p.Public <= 0 || p.Public > 65535 || p.Local <= 0 || p.Local > 65535 {
			return fmt.Errorf("watchdog.ports[%d]: invalid port", i)
		}
		if p.Check != "tls" && p.Check != "starttls" && p.Check != "banner" {
			return fmt.Errorf("watchdog.ports[%d]: check must be tls or starttls", i)
		}
	}
	return nil
}
