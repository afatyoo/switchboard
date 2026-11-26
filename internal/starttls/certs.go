package starttls

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afatyoo/switchboard/internal/cert"
)

// Certs picks a certificate by SNI from the same directory HAProxy uses, so
// `switchboard add` and `switchboard sync` cover the STARTTLS ports too.
// Files are reloaded when their modification time changes.
type Certs struct {
	Dir     string
	Default string // used when no file matches or the client sent no SNI

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	mod  time.Time
	cert *tls.Certificate
}

// Get implements tls.Config.GetCertificate.
func (c *Certs) Get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := normalizeSNI(hello.ServerName)
	if validSNI(name) {
		if crt, err := c.load(filepath.Join(c.Dir, name+".pem")); err == nil {
			return crt, nil
		}
		if i := strings.IndexByte(name, '.'); i > 0 {
			if crt, err := c.load(filepath.Join(c.Dir, "_wildcard"+name[i:]+".pem")); err == nil {
				return crt, nil
			}
		}
	}
	if c.Default == "" {
		return nil, errors.New("no certificate for the requested name")
	}
	return c.load(c.Default)
}

func (c *Certs) load(path string) (*tls.Certificate, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	if e, ok := c.cache[path]; ok && e.mod.Equal(st.ModTime()) {
		return e.cert, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// HAProxy bundles hold cert, chain and key in one file.
	crt, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, err
	}
	c.cache[path] = cached{mod: st.ModTime(), cert: &crt}
	return &crt, nil
}

// normalizeSNI lowercases a client supplied server name and drops one
// trailing dot. The result is only trusted after cert.ValidHostname.
func normalizeSNI(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// logSNI returns the server name to record in the log: the normalized name
// when it is a valid hostname, otherwise a fixed marker, so a client cannot
// inject newlines or fake fields (issue #19).
func logSNI(s string) string {
	if s == "" {
		return "-"
	}
	if n := normalizeSNI(s); validSNI(n) {
		return n
	}
	return "invalid"
}

// validSNI applies the hostname rule used for certificate files. A wildcard
// pattern is a file name form, not a name a client asks for.
func validSNI(name string) bool {
	return cert.ValidHostname(name) && !strings.HasPrefix(name, "*")
}
