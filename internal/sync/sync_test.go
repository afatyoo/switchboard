package sync

import (
	"strings"
	"testing"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/source/ldap"
	"github.com/afatyoo/switchboard/internal/testpki"
)

func domain(ca *testpki.CA, name string, vhosts []string, certNames ...string) ldap.Domain {
	c, k := ca.ValidLeaf(certNames...)
	return ldap.Domain{Name: name, VHosts: vhosts, CertPEM: string(c) + string(ca.PEM), KeyPEM: string(k)}
}

func files(m map[string][]byte) func(string) []byte {
	return func(h string) []byte { return m[h] }
}

func TestPlan(t *testing.T) {
	ca := testpki.NewCA(true)
	opts := cert.Options{Roots: ca.Pool()}
	d1 := domain(ca, "c1.test", []string{"mail.c1.test", "webmail.c1.test"}, "mail.c1.test")
	d2 := domain(ca, "c2.test", []string{"mail.c2.test"}, "mail.c2.test")

	r, err := Plan(Input{Domains: []ldap.Domain{d1, d2}, Managed: map[string]bool{}, Current: files(nil), Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Added, ",") != "mail.c1.test,mail.c2.test" {
		t.Fatalf("added = %v", r.Added)
	}
	if len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0], "webmail.c1.test") {
		t.Fatalf("skipped = %v", r.Skipped)
	}

	// Second run with the same data: nothing to do.
	installed := map[string][]byte{"mail.c1.test": r.Changes["mail.c1.test"], "mail.c2.test": r.Changes["mail.c2.test"]}
	r2, _ := Plan(Input{Domains: []ldap.Domain{d1, d2}, Managed: r.Managed, Current: files(installed), Options: opts})
	if len(r2.Changes) != 0 {
		t.Fatalf("expected no changes, got %v", keys(r2.Changes))
	}

	// Domain 2 renewed, domain 1 removed from LDAP.
	d2b := domain(ca, "c2.test", []string{"mail.c2.test"}, "mail.c2.test")
	r3, _ := Plan(Input{Domains: []ldap.Domain{d2b}, Managed: r.Managed, Current: files(installed), Options: opts})
	if strings.Join(r3.Updated, ",") != "mail.c2.test" || strings.Join(r3.Removed, ",") != "mail.c1.test" {
		t.Fatalf("updated=%v removed=%v", r3.Updated, r3.Removed)
	}
	if r3.Changes["mail.c1.test"] != nil || r3.Managed["mail.c1.test"] {
		t.Fatal("mail.c1.test should be deleted and unmanaged")
	}
}

func TestManualWins(t *testing.T) {
	ca := testpki.NewCA(true)
	d := domain(ca, "c1.test", []string{"mail.c1.test"}, "mail.c1.test")
	r, _ := Plan(Input{
		Domains: []ldap.Domain{d}, Managed: map[string]bool{},
		Current: files(map[string][]byte{"mail.c1.test": []byte("manual")}),
		Options: cert.Options{Roots: ca.Pool()},
	})
	if len(r.Changes) != 0 || r.Managed["mail.c1.test"] {
		t.Fatalf("manual file overwritten: %v", keys(r.Changes))
	}
}

func TestMaxRemove(t *testing.T) {
	managed := map[string]bool{"a.test": true, "b.test": true, "c.test": true}
	cur := map[string][]byte{"a.test": []byte("x"), "b.test": []byte("x"), "c.test": []byte("x")}
	_, err := Plan(Input{Managed: managed, Current: files(cur), MaxRemove: 2})
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestInvalidCertSkippedNotFatal(t *testing.T) {
	ca := testpki.NewCA(true)
	other := testpki.NewCA(true)
	good := domain(ca, "c1.test", []string{"mail.c1.test"}, "mail.c1.test")
	untrusted := domain(other, "c2.test", []string{"mail.c2.test"}, "mail.c2.test")
	broken := ldap.Domain{Name: "c3.test", VHosts: []string{"mail.c3.test"}, CertPEM: "garbage", KeyPEM: "garbage"}
	r, err := Plan(Input{Domains: []ldap.Domain{good, untrusted, broken}, Managed: map[string]bool{}, Current: files(nil), Options: cert.Options{Roots: ca.Pool()}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Added, ",") != "mail.c1.test" || len(r.Skipped) != 2 {
		t.Fatalf("added=%v skipped=%v", r.Added, r.Skipped)
	}
}

func keys(m map[string][]byte) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}
