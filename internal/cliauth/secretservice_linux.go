// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cliauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/godbus/dbus/v5"
	gokeyring "github.com/zalando/go-keyring"
)

// On Linux the token goes to the Secret Service keyring (GNOME Keyring,
// KWallet) when a session runs one, else to a file under
// $XDG_CONFIG_HOME/sneakers/.
func defaultStore() Store {
	config, err := os.UserConfigDir()
	if err != nil {
		return nil
	}
	return fallbackStore{keyring: newSecretService(KeychainService), file: FileStore(filepath.Join(config, "sneakers"))}
}

const secretsName = "org.freedesktop.secrets"

// secretService keeps tokens in the Secret Service's login collection, one
// item per gateway host, over the session bus.
type secretService struct {
	service string
	running func() bool
}

func newSecretService(service string) secretService {
	return secretService{service: service, running: sync.OnceValue(secretServiceRunning)}
}

// secretServiceRunning reports whether the session bus has a Secret Service
// running or ready to start. It never starts a bus to find out.
func secretServiceRunning() bool {
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if conn.Auth(nil) != nil || conn.Hello() != nil {
		return false
	}
	var owned bool
	if conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, secretsName).Store(&owned) == nil && owned {
		return true
	}
	var names []string
	if conn.BusObject().Call("org.freedesktop.DBus.ListActivatableNames", 0).Store(&names) != nil {
		return false
	}
	return slices.Contains(names, secretsName)
}

func (k secretService) Available() bool { return k.running() }

func (k secretService) check(account string) error {
	if !safeAccount.MatchString(account) {
		return fmt.Errorf("keyring: %q isn't a gateway host this store takes", account)
	}
	return nil
}

func (k secretService) Get(account string) (string, bool, error) {
	if err := k.check(account); err != nil {
		return "", false, err
	}
	token, err := gokeyring.Get(k.service, account)
	if errors.Is(err, gokeyring.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("keyring: %w", err)
	}
	return token, true, nil
}

func (k secretService) Set(account, token string) error {
	if err := k.check(account); err != nil {
		return err
	}
	if !personalToken.MatchString(token) {
		return errors.New("keyring: only a personal token is stored")
	}
	if err := gokeyring.Set(k.service, account, token); err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

func (k secretService) Delete(account string) error {
	if err := k.check(account); err != nil {
		return err
	}
	if err := gokeyring.Delete(k.service, account); err != nil && !errors.Is(err, gokeyring.ErrNotFound) {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

func (k secretService) Where(account string) string {
	return fmt.Sprintf("the Secret Service keyring (service %s, account %s)", k.service, account)
}
