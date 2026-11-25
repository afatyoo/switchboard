// Package cert parses and validates certificate bundles before they are
// handed to HAProxy.
package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Bundle is a leaf certificate, its intermediates and the matching key.
type Bundle struct {
	Leaf          *x509.Certificate
	Intermediates []*x509.Certificate
	Key           crypto.Signer
	keyPEM        []byte
}

// Options control validation.
type Options struct {
	Now      time.Time
	Roots    *x509.CertPool // nil means system roots
	WarnDays int
}

// Report is the result of a validation.
type Report struct {
	Hostname string
	Subject  string
	Issuer   string
	NotAfter time.Time
	DaysLeft int
	Warnings []string
}

var hostnameRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHostname reports whether name is safe to use as a hostname and file name.
func ValidHostname(name string) bool {
	return len(name) <= 253 && hostnameRE.MatchString(name)
}

// LoadFiles reads certificate, optional chain and key files.
func LoadFiles(certFile, chainFile, keyFile string) (*Bundle, error) {
	var data []byte
	for _, f := range []string{certFile, chainFile, keyFile} {
		if f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
		data = append(data, '\n')
	}
	return Parse(data)
}

// Parse reads PEM data holding certificates and exactly one private key.
// The first certificate is the leaf.
func Parse(data []byte) (*Bundle, error) {
	b := &Bundle{}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			certs = append(certs, c)
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			if b.Key != nil {
				return nil, errors.New("more than one private key")
			}
			k, err := parseKey(block)
			if err != nil {
				return nil, err
			}
			b.Key = k
			b.keyPEM = pem.EncodeToMemory(block)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found")
	}
	if b.Key == nil {
		return nil, errors.New("no private key found")
	}
	b.Leaf, b.Intermediates = certs[0], certs[1:]
	return b, nil
}

func parseKey(block *pem.Block) (crypto.Signer, error) {
	if block.Headers["Proc-Type"] != "" {
		return nil, errors.New("encrypted private keys are not supported")
	}
	var k any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return s, nil
}

// Validate checks that the bundle can safely serve hostname.
func (b *Bundle) Validate(hostname string, o Options) (*Report, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if !ValidHostname(hostname) {
		return nil, fmt.Errorf("invalid hostname %q", hostname)
	}
	leaf := b.Leaf

	if !publicKeysEqual(leaf.PublicKey, b.Key.Public()) {
		return nil, errors.New("private key does not match certificate")
	}
	if rk, ok := b.Key.Public().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key is %d bits, need at least 2048", rk.N.BitLen())
	}
	if err := leaf.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("certificate does not cover %s: %w", hostname, err)
	}
	if o.Now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate not valid before %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !o.Now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	if leaf.IsCA {
		return nil, errors.New("leaf certificate is a CA")
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasEKU(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("certificate is not valid for server authentication")
	}
	for _, ic := range b.Intermediates {
		if !ic.IsCA {
			return nil, fmt.Errorf("chain certificate %q is not a CA", ic.Subject.CommonName)
		}
		if ic.KeyUsage&x509.KeyUsageCertSign == 0 {
			// Strict clients (for example Python 3.13+) reject this.
			return nil, fmt.Errorf("chain certificate %q lacks keyUsage keyCertSign", ic.Subject.CommonName)
		}
	}

	inter := x509.NewCertPool()
	for _, ic := range b.Intermediates {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: inter,
		Roots:         o.Roots,
		CurrentTime:   o.Now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("chain does not verify: %w", err)
	}

	r := &Report{
		Hostname: hostname,
		Subject:  leaf.Subject.CommonName,
		Issuer:   leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter,
		DaysLeft: int(leaf.NotAfter.Sub(o.Now).Hours() / 24),
	}
	if o.WarnDays > 0 && r.DaysLeft < o.WarnDays {
		r.Warnings = append(r.Warnings, fmt.Sprintf("expires in %d days", r.DaysLeft))
	}
	return r, nil
}

// HAProxyPEM returns leaf, intermediates and key in the order HAProxy expects.
func (b *Bundle) HAProxyPEM() []byte {
	var buf bytes.Buffer
	for _, c := range append([]*x509.Certificate{b.Leaf}, b.Intermediates...) {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	buf.Write(b.keyPEM)
	return buf.Bytes()
}

func hasEKU(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, e := range c.ExtKeyUsage {
		if e == u || e == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ak := a.(type) {
	case *rsa.PublicKey:
		return ak.Equal(b)
	case *ecdsa.PublicKey:
		return ak.Equal(b)
	case ed25519.PublicKey:
		return ak.Equal(b)
	}
	return false
}
