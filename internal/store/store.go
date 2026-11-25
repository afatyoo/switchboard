// Package store installs and removes certificate files in the HAProxy
// certificate directory. Every change is checked with HAProxy before it is
// reloaded, and rolled back if the check fails.
package store

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/afatyoo/switchboard/internal/cert"
)

// HAProxy is what the store needs from HAProxy.
type HAProxy interface {
	Check() error
	Reload() error
}

// Store manages <dir>/<hostname>.pem files.
type Store struct {
	Dir     string
	Group   string // file group, empty keeps the default
	HAProxy HAProxy
}

const fileMode = 0o640

func (s *Store) path(hostname string) (string, error) {
	if !cert.ValidHostname(hostname) {
		return "", fmt.Errorf("invalid hostname %q", hostname)
	}
	// "*" is valid in a wildcard hostname but awkward in file names.
	return filepath.Join(s.Dir, strings.ReplaceAll(hostname, "*", "_wildcard")+".pem"), nil
}

// Install writes data for hostname, checks HAProxy, reloads it and restores
// the previous state if anything fails before the reload.
func (s *Store) Install(hostname string, data []byte) error {
	return s.Apply(map[string][]byte{hostname: data})
}

// Remove deletes the file for hostname, checks HAProxy and reloads it.
func (s *Store) Remove(hostname string) error {
	dst, err := s.path(hostname)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no certificate for %s", hostname)
	}
	return s.Apply(map[string][]byte{hostname: nil})
}

// Apply writes (non-nil data) or deletes (nil data) several files, then runs
// one HAProxy check. If the check fails every file is restored and HAProxy is
// not reloaded. An empty change set does nothing.
func (s *Store) Apply(changes map[string][]byte) error {
	if len(changes) == 0 {
		return nil
	}
	type undo struct {
		dst     string
		prev    []byte
		hadPrev bool
	}
	var undos []undo
	rollback := func() {
		for i := len(undos) - 1; i >= 0; i-- {
			u := undos[i]
			if u.hadPrev {
				_ = s.restore(u.dst, u.prev)
			} else {
				_ = os.Remove(u.dst)
			}
		}
	}

	hosts := make([]string, 0, len(changes))
	for h := range changes {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		dst, err := s.path(h)
		if err != nil {
			rollback()
			return err
		}
		prev, prevErr := os.ReadFile(dst)
		u := undo{dst: dst, prev: prev, hadPrev: prevErr == nil}
		if data := changes[h]; data == nil {
			if !u.hadPrev {
				continue
			}
			if err := os.Remove(dst); err != nil {
				rollback()
				return err
			}
		} else if err := s.restore(dst, data); err != nil {
			// restore writes through a staging file outside Dir, so HAProxy
			// never sees a half-written file.
			rollback()
			return err
		}
		undos = append(undos, u)
	}
	if len(undos) == 0 {
		return nil
	}
	if err := s.HAProxy.Check(); err != nil {
		rollback()
		return fmt.Errorf("rolled back: %w", err)
	}
	return s.HAProxy.Reload()
}

// Read returns the current file content for hostname, or nil if absent.
func (s *Store) Read(hostname string) ([]byte, error) {
	dst, err := s.path(hostname)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(dst)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Entry is one installed certificate.
type Entry struct {
	Hostname string
	Path     string
	Bundle   *cert.Bundle
	Err      error
}

// List returns all installed certificates sorted by hostname.
func (s *Store) List() ([]Entry, error) {
	files, err := filepath.Glob(filepath.Join(s.Dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []Entry
	for _, f := range files {
		host := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(f), ".pem"), "_wildcard", "*")
		e := Entry{Hostname: host, Path: f}
		data, err := os.ReadFile(f)
		if err == nil {
			e.Bundle, err = cert.Parse(data)
		}
		e.Err = err
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) restore(dst string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(s.Dir), ".switchboard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := s.writeFile(f, data); err != nil {
		return err
	}
	return os.Rename(f.Name(), dst)
}

func (s *Store) writeFile(f *os.File, data []byte) error {
	if err := f.Chmod(fileMode); err != nil {
		f.Close()
		return err
	}
	if s.Group != "" {
		gid, err := lookupGID(s.Group)
		if err != nil {
			f.Close()
			return err
		}
		if err := f.Chown(-1, gid); err != nil && !errors.Is(err, syscall.EPERM) {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("group %q: %w", name, err)
	}
	return strconv.Atoi(g.Gid)
}
