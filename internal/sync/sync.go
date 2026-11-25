// Package sync turns the domain certificates found in Carbonio into a set of
// changes for the store. It holds no I/O so it can be tested in isolation.
package sync

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/source/ldap"
)

// Input is everything Plan needs.
type Input struct {
	Domains []ldap.Domain
	// Managed are hostnames this sync installed earlier (from the state file).
	Managed map[string]bool
	// Current returns the installed file for a hostname, nil if none.
	Current func(hostname string) []byte
	Options cert.Options
	// MaxRemove refuses a plan that removes more than this many managed
	// hostnames at once (protects against an LDAP result that is suddenly
	// empty). 0 means no limit.
	MaxRemove int
}

// Result is the plan.
type Result struct {
	Changes  map[string][]byte // nil value means delete
	Managed  map[string]bool   // new managed set if the changes apply
	Added    []string
	Updated  []string
	Removed  []string
	Skipped  []string // human readable reasons
	Warnings []string
}

// Plan computes the changes.
func Plan(in Input) (*Result, error) {
	r := &Result{Changes: map[string][]byte{}, Managed: map[string]bool{}}
	want := map[string][]byte{}

	for _, d := range in.Domains {
		b, err := cert.Parse([]byte(d.CertPEM + "\n" + d.KeyPEM))
		if err != nil {
			r.Skipped = append(r.Skipped, fmt.Sprintf("domain %s: %v", d.Name, err))
			continue
		}
		for _, vh := range d.VHosts {
			vh = strings.ToLower(strings.TrimSpace(vh))
			if !cert.ValidHostname(vh) {
				r.Skipped = append(r.Skipped, fmt.Sprintf("%s (%s): invalid hostname", vh, d.Name))
				continue
			}
			rep, err := b.Validate(vh, in.Options)
			if err != nil {
				r.Skipped = append(r.Skipped, fmt.Sprintf("%s (%s): %v", vh, d.Name, err))
				continue
			}
			for _, w := range rep.Warnings {
				r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %s", vh, w))
			}
			if _, dup := want[vh]; dup {
				r.Skipped = append(r.Skipped, fmt.Sprintf("%s (%s): virtual hostname used by more than one domain", vh, d.Name))
				continue
			}
			want[vh] = b.HAProxyPEM()
		}
	}

	for vh, data := range want {
		cur := in.Current(vh)
		switch {
		case cur != nil && !in.Managed[vh]:
			// Installed by hand: manual always wins.
			r.Skipped = append(r.Skipped, fmt.Sprintf("%s: managed manually, not overwritten", vh))
			continue
		case cur == nil:
			r.Changes[vh] = data
			r.Added = append(r.Added, vh)
		case !bytes.Equal(cur, data):
			r.Changes[vh] = data
			r.Updated = append(r.Updated, vh)
		}
		r.Managed[vh] = true
	}
	for vh := range in.Managed {
		if _, ok := want[vh]; ok {
			continue
		}
		if in.Current(vh) == nil {
			continue // already gone, just forget it
		}
		r.Changes[vh] = nil
		r.Removed = append(r.Removed, vh)
	}
	if in.MaxRemove > 0 && len(r.Removed) > in.MaxRemove {
		return nil, fmt.Errorf("refusing to remove %d certificates at once (limit %d): %s",
			len(r.Removed), in.MaxRemove, strings.Join(sorted(r.Removed), ", "))
	}
	sort.Strings(r.Added)
	sort.Strings(r.Updated)
	sort.Strings(r.Removed)
	sort.Strings(r.Skipped)
	sort.Strings(r.Warnings)
	return r, nil
}

func sorted(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
