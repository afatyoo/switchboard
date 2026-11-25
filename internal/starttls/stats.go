package starttls

import (
	"strings"
	"sync"
	"time"

	"github.com/afatyoo/switchboard/internal/metrics"
)

// Stats counts sessions per protocol and outcome. Safe for concurrent use.
type Stats struct {
	mu     sync.Mutex
	conns  map[string]map[string]int64
	active map[string]int64
}

func (s *Stats) begin(proto string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		s.active = map[string]int64{}
	}
	s.active[proto]++
}

func (s *Stats) end(proto, result string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[proto]--
	if s.conns == nil {
		s.conns = map[string]map[string]int64{}
	}
	if s.conns[proto] == nil {
		s.conns[proto] = map[string]int64{}
	}
	s.conns[proto][category(result)]++
}

// Snapshot returns a copy for the stats file.
func (s *Stats) Snapshot() metrics.ProxyStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := metrics.ProxyStats{Time: time.Now().Unix(), Connections: map[string]map[string]int64{}, Active: map[string]int64{}}
	for p, m := range s.conns {
		out.Connections[p] = map[string]int64{}
		for r, n := range m {
			out.Connections[p][r] = n
		}
	}
	for p, n := range s.active {
		out.Active[p] = n
	}
	return out
}

// category maps a session result to a small, fixed set of label values.
func category(result string) string {
	switch {
	case result == "ok":
		return "ok"
	case result == "closed before STARTTLS":
		return "closed"
	case result == ErrTLSOnPlainPort.Error():
		return "tls_on_plain_port"
	case strings.HasPrefix(result, "too many connections"):
		return "limited"
	case strings.HasPrefix(result, "pre-TLS"):
		return "pretls_error"
	case strings.HasPrefix(result, "client TLS"):
		return "client_tls_error"
	case strings.HasPrefix(result, "upstream"):
		return "upstream_error"
	}
	return "other"
}
