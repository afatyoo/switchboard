// Package setup inspects a Carbonio node and produces a working Switchboard
// configuration: detection, rendering and applying with rollback.
package setup

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Runner runs a command and returns its combined output.
type Runner func(name string, args ...string) (string, error)

// Port is one public mail port Switchboard can take over.
type Port struct {
	Public   int
	Local    int
	Protocol string // imap, pop3, smtp
	Implicit bool   // implicit TLS (HAProxy) or STARTTLS (switchboard proxy)
}

// AllPorts lists every port Switchboard knows, in a stable order.
var AllPorts = []Port{
	{993, 10993, "imap", true},
	{995, 10995, "pop3", true},
	{465, 10465, "smtp", true},
	{587, 10587, "smtp", false},
	{143, 10143, "imap", false},
	{110, 10110, "pop3", false},
}

// Env is what detection found.
type Env struct {
	Root string // filesystem root, "/" in production

	CarbonioFound bool
	Hostname      string

	InfraCertFile string
	InfraKeyFile  string
	InfraSubject  string
	InfraNotAfter time.Time
	InfraPublic   bool   // chains to the system roots
	InfraCAFile   string // Carbonio CA that signed a self-signed infra certificate
	VerifyName    string // name HAProxy and the proxy check on Carbonio's certificate

	LDAPISocket  string // empty when not found
	MetricsDir   string // node_exporter textfile directory, empty when not found
	Ports        []Port // public ports Carbonio is listening on
	HAProxyMajor int
	HAProxyMinor int
	TPROXYOK     bool
	GlobalIPv6   []string

	Warnings []string
	Problems []string // anything that blocks setup
}

const (
	carbonioCA  = "opt/zextras/conf/ca/ca.pem"
	infraCert   = "opt/zextras/conf/nginx.crt"
	infraKey    = "opt/zextras/conf/nginx.key"
	ldapiSocket = "run/carbonio/run/ldapi"
	metricsDir  = "opt/zextras/zmstat/prometheus"
)

// Detect inspects the node. listening reports whether something accepts TCP
// connections on 127.0.0.1:port (injectable for tests).
func Detect(root string, run Runner, listening func(port int) bool) *Env {
	e := &Env{Root: root}
	p := func(rel string) string { return filepath.Join(root, rel) }

	if _, err := os.Stat(p("opt/zextras")); err == nil {
		e.CarbonioFound = true
	} else {
		e.Problems = append(e.Problems, "Carbonio not found (/opt/zextras missing); Switchboard must run on a Carbonio proxy node")
	}

	if out, err := run("runuser", "-u", "zextras", "--", "/opt/zextras/bin/zmhostname"); err == nil {
		e.Hostname = strings.TrimSpace(out)
	} else if h, err := os.Hostname(); err == nil {
		e.Hostname = h
	}

	e.detectInfraCert(p(infraCert), p(infraKey), p(carbonioCA))

	if st, err := os.Stat(p(ldapiSocket)); err == nil && st.Mode()&os.ModeSocket != 0 {
		e.LDAPISocket = "/" + ldapiSocket
	}
	if st, err := os.Stat(p(metricsDir)); err == nil && st.IsDir() {
		e.MetricsDir = "/" + metricsDir
	}

	for _, port := range AllPorts {
		if listening(port.Public) {
			e.Ports = append(e.Ports, port)
		}
	}
	if len(e.Ports) == 0 {
		e.Problems = append(e.Problems, "no Carbonio mail port (993, 995, 465, 587, 143, 110) is listening")
	}

	if out, err := run("haproxy", "-v"); err != nil {
		e.Problems = append(e.Problems, "haproxy is not installed")
	} else if maj, min, ok := parseHAProxyVersion(out); ok {
		e.HAProxyMajor, e.HAProxyMinor = maj, min
		if maj < 2 || (maj == 2 && min < 4) {
			e.Problems = append(e.Problems, fmt.Sprintf("haproxy %d.%d is too old, 2.4 or newer is needed", maj, min))
		}
	}

	if _, err := run("iptables", "-m", "socket", "--help"); err == nil {
		e.TPROXYOK = true
	} else {
		e.Problems = append(e.Problems, "iptables socket match not available (kernel xt_socket); transparent mode cannot work")
	}

	if out, err := run("ip", "-6", "-o", "addr", "show", "scope", "global"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			for i, v := range f {
				if v == "inet6" && i+1 < len(f) {
					e.GlobalIPv6 = append(e.GlobalIPv6, f[i+1])
				}
			}
		}
	}
	if len(e.GlobalIPv6) > 0 {
		e.Warnings = append(e.Warnings, fmt.Sprintf("global IPv6 address found (%s): Switchboard is IPv4 only, do not publish AAAA records for customer hostnames", strings.Join(e.GlobalIPv6, ", ")))
	}
	return e
}

func (e *Env) detectInfraCert(certPath, keyPath, caPath string) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		e.Problems = append(e.Problems, "Carbonio infrastructure certificate not readable: "+err.Error())
		return
	}
	if _, err := os.Stat(keyPath); err != nil {
		e.Problems = append(e.Problems, "Carbonio infrastructure key not readable: "+err.Error())
		return
	}
	e.InfraCertFile, e.InfraKeyFile = certPath, keyPath
	certs := parseCerts(data)
	if len(certs) == 0 {
		e.Problems = append(e.Problems, "no certificate in "+certPath)
		return
	}
	leaf := certs[0]
	e.InfraSubject = leaf.Subject.CommonName
	e.InfraNotAfter = leaf.NotAfter
	e.VerifyName = verifyName(leaf, e.Hostname)

	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if sys, err := x509.SystemCertPool(); err == nil {
		opts.Roots = sys
		if _, err := leaf.Verify(opts); err == nil {
			e.InfraPublic = true
		}
	}
	if !e.InfraPublic {
		ca, err := os.ReadFile(caPath)
		pool := x509.NewCertPool()
		if err == nil && pool.AppendCertsFromPEM(ca) {
			opts.Roots = pool
			if _, err := leaf.Verify(opts); err == nil {
				e.InfraCAFile = caPath
			}
		}
		if e.InfraCAFile == "" {
			e.Problems = append(e.Problems, "infrastructure certificate chains neither to the system roots nor to the Carbonio CA ("+caPath+")")
		} else {
			e.Warnings = append(e.Warnings, "infrastructure certificate is self-signed (Carbonio CA): customers are fine on their own hostnames, but during fail-open and for clients without SNI they see this certificate; pass --default-cert with a public certificate for the second case")
		}
	}
	if time.Until(leaf.NotAfter) < 21*24*time.Hour {
		e.Warnings = append(e.Warnings, fmt.Sprintf("infrastructure certificate expires on %s", leaf.NotAfter.Format("2006-01-02")))
	}
}

// verifyName picks a DNS name the infrastructure certificate covers, so the
// backend check (verifyhost / upstream_verify_name) succeeds.
func verifyName(c *x509.Certificate, hostname string) string {
	if hostname != "" && c.VerifyHostname(hostname) == nil {
		return hostname
	}
	for _, n := range c.DNSNames {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	for _, n := range c.DNSNames {
		if strings.HasPrefix(n, "*.") {
			return "mail" + n[1:]
		}
	}
	return c.Subject.CommonName
}

func parseCerts(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

var haproxyVersionRE = regexp.MustCompile(`(?i)HAProxy version (\d+)\.(\d+)`)

func parseHAProxyVersion(out string) (int, int, bool) {
	m := haproxyVersionRE.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj, min, true
}

// TCPListening reports whether 127.0.0.1:port accepts connections.
func TCPListening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ErrBlocked is returned when detection found problems that block setup.
var ErrBlocked = errors.New("setup blocked")
