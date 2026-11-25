package watchdog

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
)

// IPTables manages "-t nat PREROUTING ... REDIRECT" rules tagged with the
// switchboard comment, the same rules deploy/iptables/redirect.sh creates.
type IPTables struct {
	Bin string // default "iptables"
}

func (t IPTables) rule(p Port) []string {
	return []string{"-t", "nat", "PREROUTING", "-p", "tcp", "--dport", strconv.Itoa(p.Public),
		"-m", "comment", "--comment", "switchboard", "-j", "REDIRECT", "--to-ports", strconv.Itoa(p.Local)}
}

func (t IPTables) run(op string, p Port) error {
	bin := t.Bin
	if bin == "" {
		bin = "iptables"
	}
	r := t.rule(p)
	args := append([]string{"-w", r[0], r[1], op}, r[2:]...)
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", bin, args, err, out)
	}
	return nil
}

// Has reports whether the redirect for p exists.
func (t IPTables) Has(p Port) (bool, error) {
	err := t.run("-C", p)
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(errors.Unwrap(err), &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// Add inserts the redirect if it is missing.
func (t IPTables) Add(p Port) error {
	if ok, err := t.Has(p); err != nil || ok {
		return err
	}
	return t.run("-A", p)
}

// Remove deletes the redirect if present.
func (t IPTables) Remove(p Port) error {
	if ok, err := t.Has(p); err != nil || !ok {
		return err
	}
	return t.run("-D", p)
}
