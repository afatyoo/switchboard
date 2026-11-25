package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilder(t *testing.T) {
	var b Builder
	b.Gauge("sb_up", "Up.", Labels{"port": "993"}, 1)
	b.Gauge("sb_up", "Up.", Labels{"port": "587"}, 0)
	b.Counter("sb_total", "Total.", Labels{"host": `a"b`}, 3)
	got := string(b.Bytes())
	want := `# HELP sb_up Up.
# TYPE sb_up gauge
sb_up{port="993"} 1
sb_up{port="587"} 0
# HELP sb_total Total.
# TYPE sb_total counter
sb_total{host="a\"b"} 3
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteFileAndJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.prom")
	if err := WriteFile(p, []byte("a 1\n")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	s := SyncStatus{Time: 5, OK: true, Domains: 2}
	jp := filepath.Join(dir, "sub", "s.json")
	if err := WriteJSON(jp, s); err != nil {
		t.Fatal(err)
	}
	var back SyncStatus
	if err := ReadJSON(jp, &back); err != nil || back != s {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".switchboard-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	if !strings.HasSuffix(p, ".prom") {
		t.Fatal()
	}
}
