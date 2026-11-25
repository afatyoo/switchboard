// Package ldap reads per-domain certificates from Carbonio LDAP, read-only.
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Domain is a Carbonio domain with its virtual hostnames and certificate.
type Domain struct {
	Name    string
	VHosts  []string
	CertPEM string // certificate followed by its chain
	KeyPEM  string
}

// Config describes how to reach LDAP.
type Config struct {
	URL          string // ldap:// or ldaps://
	StartTLS     bool
	BindDN       string
	PasswordFile string
	// PasswordCommand prints the password on stdout. Used instead of
	// PasswordFile, for example to read it from Carbonio localconfig at run
	// time so no copy is kept on disk.
	PasswordCommand []string
	BaseDN          string // "" searches the whole tree
	CAFile          string // CA for ldaps/StartTLS, empty uses system roots
	Timeout         time.Duration
}

const filter = "(&(objectClass=zimbraDomain)(zimbraVirtualHostname=*)(zimbraSSLCertificate=*)(zimbraSSLPrivateKey=*))"

var attrs = []string{"zimbraDomainName", "zimbraVirtualHostname", "zimbraSSLCertificate", "zimbraSSLPrivateKey"}

// Fetch returns every domain that has virtual hostnames and a certificate.
func Fetch(c Config) ([]Domain, error) {
	pw, err := password(c)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap url: %w", err)
	}
	tlsCfg := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", c.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	conn, err := goldap.DialURL(c.URL, goldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(timeout)
	if c.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}
	if err := conn.Bind(c.BindDN, pw); err != nil {
		return nil, fmt.Errorf("ldap bind: %w", err)
	}

	res, err := conn.SearchWithPaging(goldap.NewSearchRequest(
		c.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, int(timeout.Seconds()), false, filter, attrs, nil), 500)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	out := make([]Domain, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, Domain{
			Name:    e.GetAttributeValue("zimbraDomainName"),
			VHosts:  e.GetAttributeValues("zimbraVirtualHostname"),
			CertPEM: e.GetAttributeValue("zimbraSSLCertificate"),
			KeyPEM:  e.GetAttributeValue("zimbraSSLPrivateKey"),
		})
	}
	return out, nil
}
