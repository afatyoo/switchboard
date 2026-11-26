package watchdog

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/afatyoo/switchboard/internal/metrics"
)

// countingFW wraps fakeFW and counts firewall changes.
type countingFW struct {
	fakeFW
	adds, removes int
}

func (f *countingFW) Add(p Port) error    { f.adds++; return f.fakeFW.Add(p) }
func (f *countingFW) Remove(p Port) error { f.removes++; return f.fakeFW.Remove(p) }

func newIntervalWatchdog(fw Firewall, healthy *bool, now *time.Time, interval time.Duration) *Watchdog {
	return &Watchdog{
		Ports:    []Port{{Public: 993, Local: 10993}},
		Firewall: fw,
		Probe: func(context.Context, Port) error {
			if *healthy {
				return nil
			}
			return errors.New("down")
		},
		FailAfter: 1, RecoverAfter: 1,
		MinFailOpenInterval: interval,
		Now:                 func() time.Time { return *now },
		Log:                 log.New(io.Discard, "", 0),
	}
}

func TestMinFailOpenIntervalLimitsFlapping(t *testing.T) {
	fw := &countingFW{fakeFW: fakeFW{rules: map[int]bool{993: true}}}
	healthy := true
	now := time.Unix(1_000_000, 0)
	w := newIntervalWatchdog(fw, &healthy, &now, time.Minute)
	ctx := context.Background()

	// The listener flips state every 5 s for 10 minutes.
	for i := 0; i < 120; i++ {
		healthy = i%2 == 0
		w.Tick(ctx)
		now = now.Add(5 * time.Second)
	}
	// Without the interval this is 60 removes and 59 adds. With it the port
	// toggles at most once per minute.
	if fw.removes > 11 || fw.adds > 11 {
		t.Fatalf("toggled too often: %d removes, %d adds", fw.removes, fw.adds)
	}
	if fw.removes == 0 {
		t.Fatal("never failed open")
	}
}

func TestMinFailOpenIntervalNeverBlocksFailOpen(t *testing.T) {
	fw := &countingFW{fakeFW: fakeFW{rules: map[int]bool{993: true}}}
	healthy := false
	now := time.Unix(1_000_000, 0)
	w := newIntervalWatchdog(fw, &healthy, &now, time.Hour)
	ctx := context.Background()

	w.Tick(ctx)
	if fw.rules[993] {
		t.Fatal("unhealthy listener did not fail open")
	}
	healthy = true
	now = now.Add(10 * time.Second)
	w.Tick(ctx)
	if fw.rules[993] {
		t.Fatal("redirect restored inside min_failopen_interval")
	}
	now = now.Add(time.Hour)
	w.Tick(ctx)
	if !fw.rules[993] {
		t.Fatal("redirect not restored after min_failopen_interval")
	}
	// Fails again right after the restore: fail-open must happen at once.
	healthy = false
	now = now.Add(time.Second)
	w.Tick(ctx)
	if fw.rules[993] {
		t.Fatal("fail-open blocked by min_failopen_interval")
	}
}

func TestFailOpenActiveSecondsMetric(t *testing.T) {
	fw := &fakeFW{rules: map[int]bool{993: true}}
	healthy := false
	now := time.Unix(1_000_000, 0)
	w := newIntervalWatchdog(fw, &healthy, &now, 0)
	w.Tick(context.Background())
	now = now.Add(90 * time.Second)
	w.Tick(context.Background())

	var b metrics.Builder
	w.Collect(&b)
	out := string(b.Bytes())
	if !strings.Contains(out, `switchboard_failopen_active_seconds{port="993"} 90`) {
		t.Fatalf("missing failopen_active_seconds 90 in:\n%s", out)
	}
}
