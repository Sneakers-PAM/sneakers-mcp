// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cliauth

import (
	"os"
	"testing"
)

// The real Secret Service, which CI's Linux job runs in its own D-Bus session.
func TestSecretServiceKeepsAToken(t *testing.T) {
	if os.Getenv("SNEAKERS_TEST_SECRET_SERVICE") != "1" {
		t.Skip("set SNEAKERS_TEST_SECRET_SERVICE=1 in a D-Bus session with an unlocked keyring")
	}
	k := newSecretService("Sneakers-PAM test")
	if !k.Available() {
		t.Fatal("no Secret Service on the session bus")
	}
	const account = "sneakers.example.org"
	t.Cleanup(func() { _ = k.Delete(account) })
	if _, ok, err := k.Get(account); err != nil || ok {
		t.Fatalf("an empty keyring gave %v %v", ok, err)
	}
	if err := k.Set(account, token); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := k.Get(account); err != nil || !ok || got != token {
		t.Fatalf("%q %v %v", got, ok, err)
	}
	if err := k.Delete(account); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := k.Get(account); err != nil || ok {
		t.Fatalf("Delete left %v %v", ok, err)
	}
	if err := k.Delete(account); err != nil {
		t.Fatalf("deleting no token: %v", err)
	}
}

// With no session bus, there is no keyring, and nothing is started to find one.
func TestSecretServiceIsAbsentWithNoSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	if newSecretService("Sneakers-PAM test").Available() {
		t.Fatal("found a keyring with no session bus")
	}
}
