package starttls

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if name != "" && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..") {
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
		return nil, errors.New("no certificate for " + name)
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
