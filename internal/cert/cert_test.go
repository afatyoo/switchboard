package cert

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/afatyoo/switchboard/internal/testpki"
)

func join(parts ...[]byte) []byte { return bytes.Join(parts, []byte("\n")) }

func TestValidBundle(t *testing.T) {
	ca := testpki.NewCA(true)
	c, k := ca.ValidLeaf("mail.customer1.test")
	b, err := Parse(join(c, k))
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Validate("mail.customer1.test", Options{Roots: ca.Pool(), WarnDays: 21})
	if err != nil {
		t.Fatal(err)
	}
	if r.DaysLeft < 88 || len(r.Warnings) != 0 {
		t.Fatalf("unexpected report %+v", r)
	}
	again, err := Parse(b.HAProxyPEM())
	if err != nil || !again.Leaf.Equal(b.Leaf) {
		t.Fatalf("HAProxyPEM round trip failed: %v", err)
	}
}

func TestRejects(t *testing.T) {
	ca := testpki.NewCA(true)
	other := testpki.NewCA(true)
	good, key := ca.ValidLeaf("mail.customer1.test")
	_, otherKey := ca.ValidLeaf("mail.customer1.test")
	expired, expKey := ca.Leaf([]string{"mail.customer1.test"}, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	future, futKey := ca.Leaf([]string{"mail.customer1.test"}, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))

	cases := []struct {
		name, host string
		data       []byte
		roots      *testpki.CA
		want       string
	}{
		{"wrong key", "mail.customer1.test", join(good, otherKey), ca, "does not match"},
		{"wrong host", "mail.customer2.test", join(good, key), ca, "does not cover"},
		{"expired", "mail.customer1.test", join(expired, expKey), ca, "expired"},
		{"not yet valid", "mail.customer1.test", join(future, futKey), ca, "not valid before"},
		{"untrusted", "mail.customer1.test", join(good, key), other, "chain does not verify"},
		{"bad hostname", "../etc/passwd", join(good, key), ca, "invalid hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Parse(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			_, err = b.Validate(tc.host, Options{Roots: tc.roots.Pool()})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestChainWithoutKeyUsageRejected(t *testing.T) {
	root := testpki.NewCA(true)
	weak := testpki.NewCA(false)
	c, k := weak.ValidLeaf("mail.customer1.test")
	b, err := Parse(join(c, weak.PEM, k))
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Validate("mail.customer1.test", Options{Roots: root.Pool()})
	if err == nil || !strings.Contains(err.Error(), "keyUsage") {
		t.Fatalf("want keyUsage error, got %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	ca := testpki.NewCA(true)
	c, k := ca.ValidLeaf("mail.customer1.test")
	for name, data := range map[string][]byte{
		"no cert":  k,
		"no key":   c,
		"two keys": join(c, k, k),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExpiryWarning(t *testing.T) {
	ca := testpki.NewCA(true)
	c, k := ca.Leaf([]string{"mail.customer1.test"}, time.Now().Add(-time.Hour), time.Now().Add(5*24*time.Hour))
	b, _ := Parse(join(c, k))
	r, err := b.Validate("mail.customer1.test", Options{Roots: ca.Pool(), WarnDays: 21})
	if err != nil || len(r.Warnings) != 1 {
		t.Fatalf("want one warning, got %v %v", r, err)
	}
}
