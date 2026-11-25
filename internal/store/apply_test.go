package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyBatchRollsBackEverything(t *testing.T) {
	h := &fakeHAProxy{}
	s := newStore(t, h)
	_ = s.Install("a.test", []byte("a1"))
	_ = s.Install("b.test", []byte("b1"))
	h.checkErr = errors.New("bad")
	err := s.Apply(map[string][]byte{"a.test": []byte("a2"), "b.test": nil, "c.test": []byte("c1")})
	if err == nil {
		t.Fatal("expected error")
	}
	for host, want := range map[string]string{"a.test": "a1", "b.test": "b1"} {
		got, _ := os.ReadFile(filepath.Join(s.Dir, host+".pem"))
		if string(got) != want {
			t.Errorf("%s = %q, want %q", host, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.test.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Error("c.test left behind")
	}
	if h.reloads != 2 {
		t.Errorf("reloads = %d, want 2", h.reloads)
	}
}

func TestApplyNoopDoesNotReload(t *testing.T) {
	h := &fakeHAProxy{}
	s := newStore(t, h)
	if err := s.Apply(map[string][]byte{"gone.test": nil}); err != nil {
		t.Fatal(err)
	}
	if h.checks != 0 || h.reloads != 0 {
		t.Fatalf("checks=%d reloads=%d", h.checks, h.reloads)
	}
}
