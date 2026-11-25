package setup

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/testpki"
)

func fakeRoot(t *testing.T, ldapi bool) string {
	t.Helper()
	root := t.TempDir()
	ca := testpki.NewCA(true)
	c, k := ca.ValidLeaf("mail-demo.example.test")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "opt/zextras/conf/ca"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "opt/zextras/zmstat/prometheus"), 0o755))
	must(os.WriteFile(filepath.Join(root, infraCert), c, 0o644))
	must(os.WriteFile(filepath.Join(root, infraKey), k, 0o600))
	must(os.WriteFile(filepath.Join(root, carbonioCA), ca.PEM, 0o644))
	if ldapi {
		must(os.MkdirAll(filepath.Join(root, "run/carbonio/run"), 0o755))
		ln, err := net.Listen("unix", filepath.Join(root, ldapiSocket))
		if err != nil {
			t.Skipf("unix socket: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
	}
	return root
}

func fakeRun(fail map[string]bool) Runner {
	return func(name string, args ...string) (string, error) {
		if fail[name] {
			return "", errors.New("fail")
		}
		switch name {
		case "runuser":
			return "mail-demo.example.test\n", nil
		case "haproxy":
			return "HAProxy version 2.8.30-0ubuntu0.24.04.2 2026/10/27\n", nil
		case "ip":
			return "", nil
		}
		return "", nil
	}
}

func all(int) bool { return true }

func TestDetectSelfSigned(t *testing.T) {
	root := fakeRoot(t, true)
	e := Detect(root, fakeRun(nil), all)
	if len(e.Problems) != 0 {
		t.Fatalf("problems: %v", e.Problems)
	}
	if e.InfraPublic || e.InfraCAFile == "" {
		t.Fatalf("want self-signed with Carbonio CA, got public=%v ca=%q", e.InfraPublic, e.InfraCAFile)
	}
	if e.VerifyName != "mail-demo.example.test" || e.Hostname != "mail-demo.example.test" {
		t.Fatalf("names: %q %q", e.VerifyName, e.Hostname)
	}
	if e.LDAPISocket == "" || e.MetricsDir == "" || len(e.Ports) != 6 || !e.TPROXYOK {
		t.Fatalf("detect: %+v", e)
	}
	if e.HAProxyMajor != 2 || e.HAProxyMinor != 8 {
		t.Fatalf("haproxy version %d.%d", e.HAProxyMajor, e.HAProxyMinor)
	}
	if len(e.Warnings) == 0 {
		t.Fatal("expected self-signed warning")
	}
}

func TestDetectProblems(t *testing.T) {
	e := Detect(t.TempDir(), fakeRun(map[string]bool{"haproxy": true, "iptables": true}), func(int) bool { return false })
	joined := strings.Join(e.Problems, "\n")
	for _, want := range []string{"Carbonio not found", "infrastructure certificate", "no Carbonio mail port", "haproxy is not installed", "socket match"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in:\n%s", want, joined)
		}
	}
}

func TestOldHAProxy(t *testing.T) {
	root := fakeRoot(t, false)
	run := func(name string, args ...string) (string, error) {
		if name == "haproxy" {
			return "HA-Proxy version 1.8.27 2021/01/01", nil
		}
		return fakeRun(nil)(name, args...)
	}
	e := Detect(root, run, all)
	if !strings.Contains(strings.Join(e.Problems, " "), "too old") && e.HAProxyMajor != 0 {
		t.Fatalf("old haproxy accepted: %v", e.Problems)
	}
}

func TestRenderLoadsAndCoversPorts(t *testing.T) {
	root := fakeRoot(t, true)
	e := Detect(root, fakeRun(nil), all)
	for _, mode := range []string{"manual", "ldap"} {
		for _, list := range []string{"", "993,587", "993,995,465", "587,143,110"} {
			ports, err := SelectPorts(e.Ports, list)
			if err != nil {
				t.Fatal(err)
			}
			o := Options{Mode: mode, Ports: ports, DefaultCert: DefaultPEM, UpstreamIP: "10.255.255.1", ExtraCA: "/etc/switchboard/extra-ca.pem"}
			if err := ValidateOptions(e, o); err != nil {
				t.Fatal(err)
			}
			cfgText, err := RenderConfig(e, o)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(p, cfgText, 0o600)
			cfg, err := config.Load(p)
			if err != nil {
				t.Fatalf("%s %q: generated config does not load: %v\n%s", mode, list, err, cfgText)
			}
			if cfg.ExtraCA != "/etc/switchboard/extra-ca.pem" {
				t.Fatalf("extra_ca not rendered: %q", cfg.ExtraCA)
			}
			if len(cfg.Watchdog.Ports) != len(ports) || cfg.Mode != mode {
				t.Fatalf("%s %q: watchdog ports %d, mode %s", mode, list, len(cfg.Watchdog.Ports), cfg.Mode)
			}
			hasStartTLS := strings.Contains(list, "587") || list == ""
			if hasStartTLS && cfg.ValidateProxy() != nil {
				t.Fatalf("%s %q: proxy section invalid: %v", mode, list, cfg.ValidateProxy())
			}
			if cfg.Proxy.UpstreamCA != CarbonioCAPath && hasStartTLS {
				t.Fatalf("self-signed infra must set upstream_ca, got %q", cfg.Proxy.UpstreamCA)
			}

			h, err := RenderHAProxy(e, o)
			if err != nil {
				t.Fatal(err)
			}
			implicit := 0
			for _, pt := range ports {
				if pt.Implicit {
					implicit++
					if !strings.Contains(string(h), "bind :"+itoa(pt.Local)+" ") {
						t.Fatalf("%q: haproxy.cfg lacks bind for %d", list, pt.Local)
					}
				}
			}
			if implicit == 0 && h != nil {
				t.Fatalf("%q: haproxy.cfg rendered without implicit ports", list)
			}
			if implicit > 0 && !strings.Contains(string(h), "ca-file "+CarbonioCAPath+" verifyhost mail-demo.example.test") {
				t.Fatalf("backend verification wrong:\n%s", h)
			}
		}
	}
}

func TestSelectPortsErrors(t *testing.T) {
	detected := AllPorts[:3]
	if _, err := SelectPorts(detected, "587"); err == nil {
		t.Fatal("port Carbonio does not listen on accepted")
	}
	if _, err := SelectPorts(detected, "25"); err == nil {
		t.Fatal("unknown port accepted")
	}
}

func TestLDAPModeNeedsSocket(t *testing.T) {
	root := fakeRoot(t, false)
	e := Detect(root, fakeRun(nil), all)
	err := ValidateOptions(e, Options{Mode: "ldap", Ports: e.Ports, DefaultCert: DefaultPEM, UpstreamIP: "10.255.255.1"})
	if err == nil || !strings.Contains(err.Error(), "ldapi") {
		t.Fatalf("want ldapi error, got %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
