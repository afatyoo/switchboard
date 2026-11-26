package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadJSONSafe(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "stats.json")
	if err := os.WriteFile(good, []byte(`{"time":42}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var s ProxyStats
	if err := ReadJSONSafe(good, 0, os.Getuid(), &s); err != nil || s.Time != 42 {
		t.Fatalf("normal file: %v %+v", err, s)
	}
	if err := ReadJSONSafe(good, 0, -1, &s); err != nil {
		t.Fatalf("no owner check: %v", err)
	}
	if err := ReadJSONSafe(good, 0, os.Getuid()+1, &s); err == nil {
		t.Fatal("wrong owner accepted")
	}

	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONSafe(link, 0, -1, &s); err == nil {
		t.Fatal("symlink accepted")
	}

	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`"`+strings.Repeat("a", 200)+`"`), 0o644); err != nil {
		t.Fatal(err)
	}
	var str string
	if err := ReadJSONSafe(big, 100, -1, &str); err == nil {
		t.Fatal("oversize file accepted")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		var fs ProxyStats
		done <- ReadJSONSafe(fifo, 0, -1, &fs)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fifo accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fifo read blocked")
	}

	if err := ReadJSONSafe(filepath.Join(dir, "missing"), 0, -1, &s); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}
