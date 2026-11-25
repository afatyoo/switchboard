// Package haproxy runs the HAProxy config check and reload commands.
package haproxy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner runs the configured commands.
type Runner struct {
	CheckCmd  []string
	ReloadCmd []string
	Timeout   time.Duration
}

// Check validates the HAProxy configuration with the current certificates.
func (r Runner) Check() error { return r.run("check", r.CheckCmd) }

// Reload asks HAProxy to load the new certificates.
func (r Runner) Reload() error { return r.run("reload", r.ReloadCmd) }

func (r Runner) run(what string, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%s command not configured", what)
	}
	t := r.Timeout
	if t == 0 {
		t = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			msg = "timed out"
		}
		return fmt.Errorf("haproxy %s failed: %w: %s", what, err, msg)
	}
	return nil
}
