package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/afatyoo/switchboard/internal/setup"
)

func execRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// cmdSetup detects the Carbonio node, writes the configuration and activates
// Switchboard port by port, rolling back if a port does not work.
func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	mode := fs.String("mode", "auto", "certificate source: manual, ldap, or auto (ldap when the Carbonio ldapi socket exists)")
	ports := fs.String("ports", "", "comma separated ports to take over (default: every Carbonio mail port that is listening)")
	defCert := fs.String("default-cert", "", "PEM bundle (cert, chain, key) for clients without SNI (default: the Carbonio infrastructure certificate)")
	extraCA := fs.String("extra-ca", "", "CA file trusted for customer certificates in addition to the system roots (private CA)")
	upstream := fs.String("upstream-ip", "10.255.255.1", "local address Switchboard uses to reach Carbonio")
	dry := fs.Bool("dry-run", false, "show what would be done and print the generated files, change nothing")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	timeout := fs.Duration("timeout", 60*time.Second, "how long to wait for every port to work before rolling back")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*dry && os.Geteuid() != 0 {
		return fmt.Errorf("setup must run as root (or use -dry-run)")
	}

	env := setup.Detect("/", execRunner, setup.TCPListening)
	printEnv(env)
	if len(env.Problems) > 0 {
		return fmt.Errorf("%w: fix the problems above and run setup again", setup.ErrBlocked)
	}

	m := *mode
	if m == "auto" {
		m = "manual"
		if env.LDAPISocket != "" {
			m = "ldap"
		}
	}
	sel, err := setup.SelectPorts(env.Ports, *ports)
	if err != nil {
		return err
	}
	bundle, err := setup.DefaultBundle(env, *defCert)
	if err != nil {
		return err
	}
	if *extraCA != "" {
		if _, err := os.Stat(*extraCA); err != nil {
			return fmt.Errorf("-extra-ca: %w", err)
		}
	}
	opts := setup.Options{Mode: m, Ports: sel, DefaultCert: setup.DefaultPEM, UpstreamIP: *upstream, ExtraCA: *extraCA}
	plan, err := setup.BuildPlan(env, opts, bundle)
	if err != nil {
		return err
	}

	fmt.Printf("\nPlan (mode %s)\n%s", m, plan.Describe())
	if *dry {
		for _, f := range plan.Files {
			if f.Path == setup.DefaultPEM {
				fmt.Printf("\n--- %s (certificate bundle, not shown)\n", f.Path)
				continue
			}
			fmt.Printf("\n--- %s\n%s", f.Path, f.Data)
		}
		fmt.Println("\ndry run: nothing changed")
		return nil
	}
	if !*yes {
		if !isTTY() {
			return fmt.Errorf("not a terminal: pass -yes to apply without confirmation")
		}
		fmt.Print("\nExisting files are backed up first. Mail ports switch to Switchboard one by one;\nif any port does not work, everything is rolled back.\nApply? [y/N] ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return fmt.Errorf("aborted, nothing changed")
		}
	}

	self, err := os.Executable()
	if err != nil {
		self = "/usr/bin/switchboard"
	}
	a := &setup.Applier{
		Root:    "/",
		Run:     execRunner,
		Log:     func(f string, v ...any) { fmt.Printf("  "+f+"\n", v...) },
		Self:    self,
		Timeout: *timeout,
	}
	fmt.Println()
	if err := a.Apply(plan); err != nil {
		return err
	}
	fmt.Printf("\nSwitchboard is active on ports %s.\n", portList(sel))
	if m == "manual" {
		fmt.Println("Add customer certificates with: switchboard add mail.customer.com -cert cert.pem -key key.pem -chain chain.pem")
	} else {
		fmt.Println("Domain certificates uploaded in Carbonio are synced every 15 minutes (switchboard sync to run it now).")
	}
	return nil
}

func printEnv(e *setup.Env) {
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Println("Detected")
	fmt.Printf("  Carbonio           %s\n", yn(e.CarbonioFound))
	fmt.Printf("  hostname           %s\n", e.Hostname)
	if e.InfraSubject != "" {
		kind := "public CA"
		if !e.InfraPublic {
			kind = "self-signed (Carbonio CA)"
		}
		fmt.Printf("  infra certificate  %s, %s, expires %s\n", e.InfraSubject, kind, e.InfraNotAfter.Format("2006-01-02"))
		fmt.Printf("  backend check name %s\n", e.VerifyName)
	}
	fmt.Printf("  LDAP socket        %s\n", orNo(e.LDAPISocket))
	fmt.Printf("  metrics directory  %s\n", orNo(e.MetricsDir))
	fmt.Printf("  mail ports         %s\n", portList(e.Ports))
	if e.HAProxyMajor > 0 {
		fmt.Printf("  haproxy            %d.%d\n", e.HAProxyMajor, e.HAProxyMinor)
	}
	fmt.Printf("  TPROXY support     %s\n", yn(e.TPROXYOK))
	for _, w := range e.Warnings {
		fmt.Printf("  warning: %s\n", w)
	}
	for _, p := range e.Problems {
		fmt.Printf("  PROBLEM: %s\n", p)
	}
}

func orNo(s string) string {
	if s == "" {
		return "not found"
	}
	return s
}

func portList(ps []setup.Port) string {
	var s []string
	for _, p := range ps {
		s = append(s, fmt.Sprint(p.Public))
	}
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func isTTY() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
