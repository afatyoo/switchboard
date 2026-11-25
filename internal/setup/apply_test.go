package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afatyoo/switchboard/internal/watchdog"
)

type recorder struct {
	mu    sync.Mutex
	calls []string
	fail  func(cmd string) bool
}

func (r *recorder) run(name string, args ...string) (string, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.mu.Lock()
	r.calls = append(r.calls, cmd)
	r.mu.Unlock()
	if r.fail != nil && r.fail(cmd) {
		return "boom", errors.New("exit 1")
	}
	return "", nil
}

func (r *recorder) has(sub string) bool {
	for _, c := range r.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func planFor(t *testing.T) (*Env, *Plan, string) {
	root := fakeRoot(t, true)
	e := Detect(root, fakeRun(nil), all)
	bundle, err := DefaultBundle(e, "")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Mode: "ldap", Ports: e.Ports, DefaultCert: DefaultPEM, UpstreamIP: "10.255.255.1"}
	p, err := BuildPlan(e, o, bundle)
	if err != nil {
		t.Fatal(err)
	}
	return e, p, root
}

func TestApplySuccess(t *testing.T) {
	_, p, root := planFor(t)
	os.MkdirAll(filepath.Join(root, "etc/haproxy"), 0o755)
	os.WriteFile(filepath.Join(root, HAProxyPath), []byte("old haproxy"), 0o644)

	r := &recorder{fail: func(c string) bool { return strings.HasPrefix(c, "systemctl is-active") }}
	a := &Applier{Root: root, Run: r.run, Log: func(string, ...any) {}, Self: "/usr/bin/switchboard",
		Timeout: 3 * time.Second, Probe: func(context.Context, watchdog.Port) error { return nil }}
	if err := a.Apply(p); err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Files {
		got, err := os.ReadFile(filepath.Join(root, f.Path))
		if err != nil || string(got) != string(f.Data) {
			t.Fatalf("%s not written", f.Path)
		}
	}
	if baks, _ := filepath.Glob(filepath.Join(root, HAProxyPath+".switchboard-backup-*")); len(baks) != 1 {
		t.Fatalf("old haproxy.cfg not backed up: %v", baks)
	}
	for _, want := range []string{"haproxy -c", "enable --now switchboard-tproxy", "restart haproxy", "restart switchboard-proxy", "/usr/bin/switchboard sync", "switchboard-sync.timer", "restart switchboard-watchdog"} {
		if !r.has(want) {
			t.Errorf("missing step %q in %v", want, r.calls)
		}
	}
}

func TestApplyRollsBackWhenPortsFail(t *testing.T) {
	_, p, root := planFor(t)
	os.MkdirAll(filepath.Join(root, "etc/haproxy"), 0o755)
	os.WriteFile(filepath.Join(root, HAProxyPath), []byte("old haproxy"), 0o644)

	r := &recorder{fail: func(c string) bool { return c == "systemctl is-active --quiet haproxy" && false }}
	a := &Applier{Root: root, Run: r.run, Log: func(string, ...any) {}, Self: "/usr/bin/switchboard",
		Timeout: 2 * time.Second, Probe: func(context.Context, watchdog.Port) error { return errors.New("no greeting") }}
	err := a.Apply(p)
	if err == nil || !strings.Contains(err.Error(), "no greeting") {
		t.Fatalf("want verification error, got %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, HAProxyPath))
	if string(got) != "old haproxy" {
		t.Fatalf("haproxy.cfg not restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, ConfigPath)); !os.IsNotExist(err) {
		t.Fatal("new config.yaml left behind after rollback")
	}
	if !r.has("redirect-rollback.sh") || !r.has("stop switchboard-watchdog") {
		t.Fatalf("ports not handed back: %v", r.calls)
	}
	// services that were active before are restarted with the old config
	if !r.has("systemctl restart haproxy") {
		t.Fatalf("haproxy not restored: %v", r.calls)
	}
}

func TestInvalidHAProxyConfigActivatesNothing(t *testing.T) {
	_, p, root := planFor(t)
	r := &recorder{fail: func(c string) bool { return strings.HasPrefix(c, "haproxy -c") }}
	a := &Applier{Root: root, Run: r.run, Log: func(string, ...any) {}, Self: "x", Timeout: time.Second}
	if err := a.Apply(p); err == nil {
		t.Fatal("expected error")
	}
	if r.has("enable") || r.has("restart") {
		t.Fatalf("services touched after failed haproxy -c: %v", r.calls)
	}
	if _, err := os.Stat(filepath.Join(root, ConfigPath)); !os.IsNotExist(err) {
		t.Fatal("files left behind")
	}
}
