package setup

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/watchdog"
)

// File is one file setup writes.
type File struct {
	Path  string
	Data  []byte
	Mode  os.FileMode
	Group string // empty keeps root
}

// Plan is everything setup will do.
type Plan struct {
	Files     []File
	Dirs      []File // Data unused
	Implicit  bool
	StartTLS  bool
	LDAP      bool
	Ports     []Port
	backups   map[string]string // path -> backup path ("" = did not exist)
	wasActive map[string]bool
}

// BuildPlan renders every file for the chosen options.
// defaultBundle is written to DefaultPEM (see DefaultBundle).
func BuildPlan(e *Env, o Options, defaultBundle []byte) (*Plan, error) {
	if err := ValidateOptions(e, o); err != nil {
		return nil, err
	}
	cfg, err := RenderConfig(e, o)
	if err != nil {
		return nil, err
	}
	p := &Plan{Ports: o.Ports, LDAP: o.Mode == "ldap"}
	for _, port := range o.Ports {
		if port.Implicit {
			p.Implicit = true
		} else {
			p.StartTLS = true
		}
	}
	p.Dirs = []File{
		{Path: "/etc/switchboard", Mode: 0o750, Group: "haproxy"},
		{Path: CertDir, Mode: 0o750, Group: "haproxy"},
		{Path: "/var/lib/switchboard", Mode: 0o750},
	}
	p.Files = append(p.Files, File{Path: ConfigPath, Data: cfg, Mode: 0o640, Group: "haproxy"})
	p.Files = append(p.Files, File{Path: DefaultPEM, Data: defaultBundle, Mode: 0o640, Group: "haproxy"})
	if p.Implicit {
		h, err := RenderHAProxy(e, o)
		if err != nil {
			return nil, err
		}
		p.Files = append(p.Files, File{Path: HAProxyPath, Data: h, Mode: 0o644})
	}
	if !e.InfraPublic {
		ca, err := os.ReadFile(e.InfraCAFile)
		if err != nil {
			return nil, err
		}
		p.Files = append(p.Files, File{Path: CarbonioCAPath, Data: ca, Mode: 0o644})
	}
	return p, nil
}

// DefaultBundle returns the HAProxy bundle (certificate, chain, key) to use for
// clients without SNI: the given file, or the infrastructure certificate.
func DefaultBundle(e *Env, given string) ([]byte, error) {
	var data []byte
	var err error
	if given != "" {
		data, err = os.ReadFile(given)
	} else {
		var c, k []byte
		if c, err = os.ReadFile(e.InfraCertFile); err == nil {
			if k, err = os.ReadFile(e.InfraKeyFile); err == nil {
				data = append(append(append([]byte{}, c...), '\n'), k...)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	b, err := cert.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("default certificate: %w", err)
	}
	return b.HAProxyPEM(), nil
}

// Describe lists the plan for the admin.
func (p *Plan) Describe() string {
	var b strings.Builder
	b.WriteString("Files:\n")
	for _, f := range p.Files {
		fmt.Fprintf(&b, "  write  %s (%d bytes)\n", f.Path, len(f.Data))
	}
	b.WriteString("Services:\n")
	b.WriteString("  enable switchboard-tproxy (TPROXY routing, upstream address, port guard)\n")
	if p.Implicit {
		b.WriteString("  enable haproxy (restart)\n")
	}
	if p.StartTLS {
		b.WriteString("  enable switchboard-proxy (restart)\n")
	}
	if p.LDAP {
		b.WriteString("  run    switchboard sync, enable switchboard-sync.timer\n")
	}
	b.WriteString("  enable switchboard-check.timer\n")
	b.WriteString("  enable switchboard-watchdog (adds the port redirects once listeners answer)\n")
	b.WriteString("Ports: ")
	for i, port := range p.Ports {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Itoa(port.Public))
	}
	b.WriteString("\n")
	return b.String()
}

// Applier performs a plan on a real system.
type Applier struct {
	Root    string // "/" in production
	Run     Runner
	Log     func(format string, args ...any)
	Self    string // path of the switchboard binary, for the first sync
	Timeout time.Duration
	Probe   func(ctx context.Context, p watchdog.Port) error
	Now     func() time.Time
}

func (a *Applier) path(p string) string { return filepath.Join(a.Root, p) }

// Apply writes files, activates services, verifies every port and rolls back
// on failure.
func (a *Applier) Apply(p *Plan) error {
	if a.Timeout == 0 {
		a.Timeout = 60 * time.Second
	}
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.Probe == nil {
		a.Probe = watchdog.DefaultProbe
	}
	p.wasActive = map[string]bool{}
	for _, u := range []string{"haproxy", "switchboard-proxy", "switchboard-watchdog"} {
		_, err := a.Run("systemctl", "is-active", "--quiet", u)
		p.wasActive[u] = err == nil
	}

	if err := a.writeFiles(p); err != nil {
		a.restoreFiles(p)
		return err
	}
	if p.Implicit {
		if out, err := a.Run("haproxy", "-c", "-q", "-f", HAProxyPath); err != nil {
			a.restoreFiles(p)
			return fmt.Errorf("generated haproxy.cfg is invalid, nothing activated: %v %s", err, out)
		}
	}
	if err := a.activate(p); err != nil {
		a.Log("activation failed: %v", err)
		a.rollback(p)
		return err
	}
	if err := a.verify(p); err != nil {
		a.Log("verification failed: %v", err)
		a.rollback(p)
		return err
	}
	return nil
}

func (a *Applier) writeFiles(p *Plan) error {
	p.backups = map[string]string{}
	stamp := a.Now().Format("20060102-150405")
	for _, d := range p.Dirs {
		if err := os.MkdirAll(a.path(d.Path), d.Mode); err != nil {
			return err
		}
		if err := a.own(a.path(d.Path), d.Mode, d.Group); err != nil {
			return err
		}
	}
	for _, f := range p.Files {
		dst := a.path(f.Path)
		if old, err := os.ReadFile(dst); err == nil {
			bak := dst + ".switchboard-backup-" + stamp
			if err := os.WriteFile(bak, old, 0o600); err != nil {
				return err
			}
			p.backups[f.Path] = bak
			a.Log("backup %s -> %s", f.Path, bak)
		} else {
			p.backups[f.Path] = ""
		}
		tmp := dst + ".switchboard-new"
		if err := os.WriteFile(tmp, f.Data, f.Mode); err != nil {
			return err
		}
		if err := a.own(tmp, f.Mode, f.Group); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		a.Log("wrote %s", f.Path)
	}
	return nil
}

func (a *Applier) own(path string, mode os.FileMode, group string) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if group == "" || os.Geteuid() != 0 {
		return nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return nil // group missing (haproxy not installed yet): keep root
	}
	gid, _ := strconv.Atoi(g.Gid)
	return os.Chown(path, 0, gid)
}

func (a *Applier) restoreFiles(p *Plan) {
	for _, f := range p.Files {
		bak, ok := p.backups[f.Path]
		if !ok {
			continue
		}
		dst := a.path(f.Path)
		if bak == "" {
			os.Remove(dst)
			a.Log("removed %s", f.Path)
			continue
		}
		if data, err := os.ReadFile(bak); err == nil {
			os.WriteFile(dst, data, f.Mode)
			a.own(dst, f.Mode, f.Group)
			a.Log("restored %s", f.Path)
		}
	}
}

func (a *Applier) step(name string, args ...string) error {
	out, err := a.Run(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func (a *Applier) activate(p *Plan) error {
	steps := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "switchboard-tproxy"},
		// idempotent, makes sure rules exist even if the unit was already active
		{"/usr/lib/switchboard/tproxy-setup.sh"},
		{"/usr/lib/switchboard/guard.sh"},
	}
	if p.Implicit {
		steps = append(steps, []string{"systemctl", "enable", "haproxy"}, []string{"systemctl", "restart", "haproxy"})
	}
	if p.StartTLS {
		steps = append(steps, []string{"systemctl", "enable", "switchboard-proxy"}, []string{"systemctl", "restart", "switchboard-proxy"})
	}
	for _, s := range steps {
		a.Log("run %s", strings.Join(s, " "))
		if err := a.step(s[0], s[1:]...); err != nil {
			return err
		}
	}
	if p.LDAP {
		a.Log("run switchboard sync")
		if out, err := a.Run(a.Self, "sync"); err != nil {
			// A failed first sync is reported but does not block: manual
			// certificates and the default certificate still work.
			a.Log("first sync failed (fix and run 'switchboard sync'): %v %s", err, strings.TrimSpace(out))
		}
		if err := a.step("systemctl", "enable", "--now", "switchboard-sync.timer"); err != nil {
			return err
		}
	}
	for _, s := range [][]string{
		{"systemctl", "enable", "--now", "switchboard-check.timer"},
		{"systemctl", "enable", "switchboard-watchdog"},
		{"systemctl", "restart", "switchboard-watchdog"},
	} {
		a.Log("run %s", strings.Join(s, " "))
		if err := a.step(s[0], s[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// verify waits until every selected port is redirected and answers through
// Switchboard.
func (a *Applier) verify(p *Plan) error {
	deadline := a.Now().Add(a.Timeout)
	pending := map[int]Port{}
	for _, port := range p.Ports {
		pending[port.Public] = port
	}
	var last map[int]string
	for {
		last = map[int]string{}
		for pub, port := range pending {
			if _, err := a.Run("iptables", "-w", "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", strconv.Itoa(pub),
				"-m", "comment", "--comment", "switchboard", "-j", "REDIRECT", "--to-ports", strconv.Itoa(port.Local)); err != nil {
				last[pub] = "redirect not active yet"
				continue
			}
			check := "banner"
			if port.Implicit {
				check = "tls"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := a.Probe(ctx, watchdog.Port{Public: pub, Local: port.Local, Check: check})
			cancel()
			if err != nil {
				last[pub] = err.Error()
				continue
			}
			a.Log("port %d ok", pub)
			delete(pending, pub)
		}
		if len(pending) == 0 {
			return nil
		}
		if a.Now().After(deadline) {
			var msg []string
			for pub, why := range last {
				msg = append(msg, fmt.Sprintf("%d: %s", pub, why))
			}
			return fmt.Errorf("ports not working after %s: %s", a.Timeout, strings.Join(msg, "; "))
		}
		time.Sleep(2 * time.Second)
	}
}

// rollback hands the ports back to Carbonio and restores the previous files
// and services.
func (a *Applier) rollback(p *Plan) {
	a.Log("rolling back")
	a.Run("systemctl", "stop", "switchboard-watchdog")
	a.Run("/usr/lib/switchboard/redirect-rollback.sh")
	a.restoreFiles(p)
	for _, u := range []string{"haproxy", "switchboard-proxy", "switchboard-watchdog"} {
		if p.wasActive[u] {
			a.Run("systemctl", "restart", u)
		} else {
			a.Run("systemctl", "disable", "--now", u)
		}
	}
	a.Log("rollback done: mail ports go straight to Carbonio unless the previous setup was active")
}
