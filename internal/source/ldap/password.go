package ldap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func password(c Config) (string, error) {
	var raw []byte
	var err error
	switch {
	case len(c.PasswordCommand) > 0:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, c.PasswordCommand[0], c.PasswordCommand[1:]...)
		cmd.Stderr = nil // never echo the command's stderr, it may hold secrets
		raw, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("ldap password command failed: %w", err)
		}
	case c.PasswordFile != "":
		raw, err = os.ReadFile(c.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("ldap password file: %w", err)
		}
	default:
		return "", errors.New("no ldap password source configured")
	}
	pw := strings.TrimSpace(string(raw))
	if pw == "" || strings.Contains(pw, "\n") {
		return "", errors.New("ldap password source returned an empty or multi-line value")
	}
	return pw, nil
}
