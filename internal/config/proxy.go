package config

import (
	"errors"
	"fmt"
)

// Proxy configures `switchboard proxy`, the STARTTLS proxy for ports 587,
// 143 and 110.
type Proxy struct {
	DefaultCert        string          `yaml:"default_cert"`
	Banner             string          `yaml:"banner"`
	Transparent        bool            `yaml:"transparent"`
	UpstreamVerifyName string          `yaml:"upstream_verify_name"`
	UpstreamCA         string          `yaml:"upstream_ca"`
	MaxPerIP           int             `yaml:"max_per_ip"`
	Listeners          []ProxyListener `yaml:"listeners"`
}

// ProxyListener is one protocol on one port.
type ProxyListener struct {
	Protocol string `yaml:"protocol"` // smtp | imap | pop3
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
}

// ValidateProxy checks the proxy section. It is only required by `proxy`.
func (c Config) ValidateProxy() error {
	p := c.Proxy
	if len(p.Listeners) == 0 {
		return errors.New("proxy.listeners is empty")
	}
	if p.Banner == "" || p.UpstreamVerifyName == "" {
		return errors.New("proxy.banner and proxy.upstream_verify_name are required")
	}
	for i, l := range p.Listeners {
		switch l.Protocol {
		case "smtp", "imap", "pop3":
		default:
			return fmt.Errorf("proxy.listeners[%d]: unknown protocol %q", i, l.Protocol)
		}
		if l.Listen == "" || l.Upstream == "" {
			return fmt.Errorf("proxy.listeners[%d]: listen and upstream are required", i)
		}
	}
	return nil
}
