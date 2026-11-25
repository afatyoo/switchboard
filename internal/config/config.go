// Package config loads the Switchboard configuration file.
package config

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the content of /etc/switchboard/config.yaml.
type Config struct {
	Mode     string `yaml:"mode"`      // manual (ldap planned)
	CertDir  string `yaml:"cert_dir"`  // HAProxy crt directory
	Group    string `yaml:"group"`     // group owning certificate files
	ExtraCA  string `yaml:"extra_ca"`  // optional CA file trusted in addition to system roots
	WarnDays int    `yaml:"warn_days"` // warn when fewer days are left
	LockFile string `yaml:"lock_file"`
	HAProxy  struct {
		CheckCmd  []string      `yaml:"check_cmd"`
		ReloadCmd []string      `yaml:"reload_cmd"`
		Timeout   time.Duration `yaml:"timeout"`
	} `yaml:"haproxy"`
}

// Default returns the default configuration.
func Default() Config {
	var c Config
	c.Mode = "manual"
	c.CertDir = "/etc/haproxy/certs"
	c.Group = "haproxy"
	c.WarnDays = 21
	c.LockFile = "/run/switchboard.lock"
	c.HAProxy.CheckCmd = []string{"haproxy", "-c", "-q", "-f", "/etc/haproxy/haproxy.cfg"}
	c.HAProxy.ReloadCmd = []string{"systemctl", "reload", "haproxy"}
	c.HAProxy.Timeout = 30 * time.Second
	return c
}

// Load reads path on top of the defaults. A missing file yields the defaults.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, c.validate()
	}
	if err != nil {
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	switch c.Mode {
	case "manual":
	case "ldap":
		return errors.New("mode ldap is not implemented yet (planned for v0.2.0)")
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if c.CertDir == "" {
		return errors.New("cert_dir is required")
	}
	return nil
}

// Roots returns the system roots plus ExtraCA, if set.
func (c Config) Roots() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if c.ExtraCA == "" {
		return pool, nil
	}
	pem, err := os.ReadFile(c.ExtraCA)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", c.ExtraCA)
	}
	return pool, nil
}
