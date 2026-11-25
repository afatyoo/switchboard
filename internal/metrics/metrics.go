// Package metrics writes Prometheus text exposition files and the small JSON
// status files that Switchboard processes share with each other.
//
// Metrics are published through the node_exporter textfile collector, so no
// extra scrape job is needed on Prometheus.
package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Builder collects metric families and renders them in text format.
type Builder struct {
	fams  map[string]*family
	order []string
}

type family struct {
	help, typ string
	samples   []string
}

// Labels is a set of label pairs.
type Labels map[string]string

func (l Labels) String() string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + `="` + escape(l[k]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// Gauge adds a gauge sample.
func (b *Builder) Gauge(name, help string, labels Labels, v float64) {
	b.add(name, help, "gauge", labels, v)
}

// Counter adds a counter sample.
func (b *Builder) Counter(name, help string, labels Labels, v float64) {
	b.add(name, help, "counter", labels, v)
}

func (b *Builder) add(name, help, typ string, labels Labels, v float64) {
	if b.fams == nil {
		b.fams = map[string]*family{}
	}
	f, ok := b.fams[name]
	if !ok {
		f = &family{help: help, typ: typ}
		b.fams[name] = f
		b.order = append(b.order, name)
	}
	f.samples = append(f.samples, name+labels.String()+" "+strconv.FormatFloat(v, 'g', -1, 64))
}

// Bytes renders the exposition text.
func (b *Builder) Bytes() []byte {
	var buf bytes.Buffer
	for _, n := range b.order {
		f := b.fams[n]
		fmt.Fprintf(&buf, "# HELP %s %s\n# TYPE %s %s\n", n, f.help, n, f.typ)
		for _, s := range f.samples {
			buf.WriteString(s)
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// WriteFile writes data atomically with mode 0644 (readable by node_exporter).
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".switchboard-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteJSON writes v as JSON atomically.
func WriteJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(b, '\n'))
}

// ReadJSON reads JSON into v. A missing file returns os.ErrNotExist.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ProxyStats is the snapshot `switchboard proxy` writes for the watchdog.
type ProxyStats struct {
	Time        int64                       `json:"time"`
	Connections map[string]map[string]int64 `json:"connections"` // protocol -> result -> count
	Active      map[string]int64            `json:"active"`      // protocol -> open sessions
}

// SyncStatus is what `switchboard sync` writes after each run.
type SyncStatus struct {
	Time     int64  `json:"time"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Domains  int    `json:"domains"`
	Changes  int    `json:"changes"`
	Skipped  int    `json:"skipped"`
	Warnings int    `json:"warnings"`
}
