package main

import (
	"fmt"

	"github.com/afatyoo/switchboard/internal/cert"
	"github.com/afatyoo/switchboard/internal/config"
	"github.com/afatyoo/switchboard/internal/source/ldap"
	"github.com/afatyoo/switchboard/internal/store"
	"github.com/afatyoo/switchboard/internal/sync"
)

func cmdSync(cfg config.Config, st *store.Store, opts cert.Options, dry bool) error {
	domains, err := ldap.Fetch(ldap.Config{
		URL:          cfg.LDAP.URL,
		StartTLS:     cfg.LDAP.StartTLS,
		BindDN:       cfg.LDAP.BindDN,
		PasswordFile: cfg.LDAP.PasswordFile,
		BaseDN:       cfg.LDAP.BaseDN,
		CAFile:       cfg.LDAP.CAFile,
		Timeout:      cfg.LDAP.Timeout,
	})
	if err != nil {
		// Never touch installed certificates when LDAP is unreachable.
		return err
	}
	managed, err := sync.LoadState(cfg.LDAP.StateFile)
	if err != nil {
		return fmt.Errorf("state file: %w", err)
	}
	var readErr error
	plan, err := sync.Plan(sync.Input{
		Domains: domains,
		Managed: managed,
		Current: func(h string) []byte {
			b, err := st.Read(h)
			if err != nil && readErr == nil {
				readErr = err
			}
			return b
		},
		Options:   opts,
		MaxRemove: cfg.LDAP.MaxRemove,
	})
	if err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}

	fmt.Printf("ldap: %d domain(s) with virtual hostnames and a certificate\n", len(domains))
	for _, h := range plan.Added {
		fmt.Println("add     ", h)
	}
	for _, h := range plan.Updated {
		fmt.Println("update  ", h)
	}
	for _, h := range plan.Removed {
		fmt.Println("remove  ", h)
	}
	for _, s := range plan.Skipped {
		fmt.Println("skip    ", s)
	}
	for _, w := range plan.Warnings {
		fmt.Println("warning ", w)
	}
	if len(plan.Changes) == 0 {
		fmt.Println("no changes")
		return sync.SaveState(cfg.LDAP.StateFile, plan.Managed)
	}
	if dry {
		fmt.Println("dry run, nothing changed")
		return nil
	}
	if err := st.Apply(plan.Changes); err != nil {
		return err
	}
	if err := sync.SaveState(cfg.LDAP.StateFile, plan.Managed); err != nil {
		return err
	}
	fmt.Printf("%d change(s) applied, HAProxy reloaded\n", len(plan.Changes))
	return nil
}

// forgetManaged drops hostname from the sync state after a manual change.
func forgetManaged(cfg config.Config, hostname string) error {
	if cfg.Mode != "ldap" {
		return nil
	}
	m, err := sync.LoadState(cfg.LDAP.StateFile)
	if err != nil || !m[hostname] {
		return err
	}
	delete(m, hostname)
	return sync.SaveState(cfg.LDAP.StateFile, m)
}
