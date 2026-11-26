package sync

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveStateIgnoresPlantedTempSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(path, map[string]bool{"mail.example.com": true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("symlink at old temp path followed: %q", got)
	}
	m, err := LoadState(path)
	if err != nil || !m["mail.example.com"] || len(m) != 1 {
		t.Fatalf("LoadState: %v %v", m, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi, err)
	}
}
