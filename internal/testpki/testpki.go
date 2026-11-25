// Package testpki creates throwaway certificates for tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewCA creates a CA. keyUsage false omits the keyUsage extension.
func NewCA(keyUsage bool) *CA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if keyUsage {
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: k, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool returns a pool holding the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Leaf issues a server certificate. It returns cert PEM and key PEM.
func (ca *CA) Leaf(names []string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, t, ca.Cert, &k.PublicKey, ca.Key)
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

// ValidLeaf issues a certificate valid for 90 days.
func (ca *CA) ValidLeaf(names ...string) (certPEM, keyPEM []byte) {
	return ca.Leaf(names, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
}
