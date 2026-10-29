// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func defaultStore() Store { return keychain{service: KeychainService} }

// keychain keeps tokens in the login Keychain as generic passwords, through
// /usr/bin/security. A token is written on its interactive mode's standard
// input, never on a command line, where any process on the machine could
// read it.
type keychain struct{ service string }

const securityTool = "/usr/bin/security"

// errItemNotFound is security(1)'s exit status for a missing item.
const errItemNotFound = 44

var (
	safeService = regexp.MustCompile(`^[A-Za-z0-9 ._-]+$`)
	safeAccount = regexp.MustCompile(`^[a-z0-9.:\[\]-]+$`)
)

func (k keychain) check(account string) error {
	if !safeService.MatchString(k.service) || !safeAccount.MatchString(account) {
		return fmt.Errorf("keychain: %q isn't a gateway host this store takes", account)
	}
	return nil
}

func (k keychain) Get(account string) (string, bool, error) {
	if err := k.check(account); err != nil {
		return "", false, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(securityTool, "find-generic-password", "-s", k.service, "-a", account, "-w") // #nosec G204 -- fixed tool, checked arguments
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == errItemNotFound {
			return "", false, nil
		}
		return "", false, fmt.Errorf("keychain: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimRight(stdout.String(), "\n"), true, nil
}

func (k keychain) Set(account, token string) error {
	if err := k.check(account); err != nil {
		return err
	}
	if !personalToken.MatchString(token) {
		return errors.New("keychain: only a personal token is stored")
	}
	var out bytes.Buffer
	cmd := exec.Command(securityTool, "-i") // #nosec G204 -- fixed tool; the command goes on stdin
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s \"%s\" -a \"%s\" -l \"%s (%s)\" -w \"%s\"\n", k.service, account, k.service, account, token))
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain: %w: %s", err, strings.TrimSpace(out.String()))
	}
	// The interactive mode exits 0 whatever its commands did; read the item
	// back to know it's there.
	got, ok, err := k.Get(account)
	if err != nil {
		return err
	}
	if !ok || got != token {
		return fmt.Errorf("keychain: the token wasn't stored: %s", strings.TrimSpace(out.String()))
	}
	return nil
}

func (k keychain) Delete(account string) error {
	if err := k.check(account); err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd := exec.Command(securityTool, "delete-generic-password", "-s", k.service, "-a", account) // #nosec G204 -- fixed tool, checked arguments
	cmd.Stdout, cmd.Stderr = nil, &stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == errItemNotFound {
			return nil
		}
		return fmt.Errorf("keychain: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
