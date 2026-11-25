package ldap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordSources(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(f, []byte("from-file\n"), 0o600)

	cases := []struct {
		name string
		cfg  Config
		want string
		ok   bool
	}{
		{"file", Config{PasswordFile: f}, "from-file", true},
		{"command wins", Config{PasswordFile: f, PasswordCommand: []string{"echo", "from-cmd"}}, "from-cmd", true},
		{"command fails", Config{PasswordCommand: []string{"false"}}, "", false},
		{"empty", Config{PasswordCommand: []string{"true"}}, "", false},
		{"multi line", Config{PasswordCommand: []string{"printf", "a\nb\n"}}, "", false},
		{"none", Config{}, "", false},
	}
	for _, tc := range cases {
		got, err := password(tc.cfg)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("%s: got %q, %v", tc.name, got, err)
		}
	}
}
