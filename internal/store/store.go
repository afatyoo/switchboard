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
	dst, err := s.path(hostname)
	if err != nil {
		return err
	}
	prev, prevErr := os.ReadFile(dst)
	hadPrev := prevErr == nil

	// Staging file lives outside Dir so HAProxy never loads a half-written
	// file, but on the same filesystem so the rename is atomic.
	tmp, err := os.CreateTemp(filepath.Dir(s.Dir), ".switchboard-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := s.writeFile(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}

	if err := s.HAProxy.Check(); err != nil {
		if hadPrev {
			_ = s.restore(dst, prev)
		} else {
			_ = os.Remove(dst)
		}
		return fmt.Errorf("rolled back: %w", err)
	}
	return s.HAProxy.Reload()
}

// Remove deletes the file for hostname, checks HAProxy and reloads it.
func (s *Store) Remove(hostname string) error {
	dst, err := s.path(hostname)
	if err != nil {
		return err
	}
	prev, err := os.ReadFile(dst)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no certificate for %s", hostname)
		}
		return err
	}
	if err := os.Remove(dst); err != nil {
		return err
	}
	if err := s.HAProxy.Check(); err != nil {
		_ = s.restore(dst, prev)
		return fmt.Errorf("rolled back: %w", err)
	}
	return s.HAProxy.Reload()
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
