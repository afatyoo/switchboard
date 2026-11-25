package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeHAProxy struct {
	checkErr error
	checks   int
	reloads  int
}

func (f *fakeHAProxy) Check() error  { f.checks++; return f.checkErr }
func (f *fakeHAProxy) Reload() error { f.reloads++; return nil }

func newStore(t *testing.T, h *fakeHAProxy) *Store {
	dir := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return &Store{Dir: dir, HAProxy: h}
}

func TestInstallAndRemove(t *testing.T) {
	h := &fakeHAProxy{}
	s := newStore(t, h)
	if err := s.Install("mail.customer1.test", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "mail.customer1.test.pem")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("file missing or wrong mode: %v %v", st, err)
	}
	if h.reloads != 1 {
		t.Fatalf("reloads = %d", h.reloads)
	}
	if err := s.Remove("mail.customer1.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file still present")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(s.Dir), ".switchboard-*")); len(left) != 0 {
		t.Fatalf("staging files left: %v", left)
	}
}

func TestFailedCheckRestoresPrevious(t *testing.T) {
	h := &fakeHAProxy{}
	s := newStore(t, h)
	if err := s.Install("mail.customer1.test", []byte("good")); err != nil {
		t.Fatal(err)
	}
	h.checkErr = errors.New("bad config")
	if err := s.Install("mail.customer1.test", []byte("bad")); err == nil {
		t.Fatal("expected error")
	}
	got, _ := os.ReadFile(filepath.Join(s.Dir, "mail.customer1.test.pem"))
	if string(got) != "good" {
		t.Fatalf("previous file not restored, got %q", got)
	}
	if h.reloads != 1 {
		t.Fatalf("reload ran after failed check: %d", h.reloads)
	}
}

func TestFailedCheckRemovesNewFile(t *testing.T) {
	h := &fakeHAProxy{checkErr: errors.New("bad")}
	s := newStore(t, h)
	if err := s.Install("mail.customer2.test", []byte("x")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "mail.customer2.test.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new file left after failed check")
	}
}

func TestFailedCheckOnRemoveRestores(t *testing.T) {
	h := &fakeHAProxy{}
	s := newStore(t, h)
	_ = s.Install("mail.customer1.test", []byte("keep"))
	h.checkErr = errors.New("bad")
	if err := s.Remove("mail.customer1.test"); err == nil {
		t.Fatal("expected error")
	}
	if got, _ := os.ReadFile(filepath.Join(s.Dir, "mail.customer1.test.pem")); string(got) != "keep" {
		t.Fatal("file not restored after failed remove")
	}
}

func TestRejectsUnsafeHostname(t *testing.T) {
	s := newStore(t, &fakeHAProxy{})
	for _, h := range []string{"../x", "a/b", "", "UPPER.test"} {
		if err := s.Install(h, []byte("x")); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestWildcardFileName(t *testing.T) {
	s := newStore(t, &fakeHAProxy{})
	if err := s.Install("*.customer3.test", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "_wildcard.customer3.test.pem")); err != nil {
		t.Fatal(err)
	}
	es, _ := s.List()
	if len(es) != 1 || es[0].Hostname != "*.customer3.test" {
		t.Fatalf("list = %+v", es)
	}
}
