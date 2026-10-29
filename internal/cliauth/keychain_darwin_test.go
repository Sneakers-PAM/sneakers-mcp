// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"strings"
	"testing"
)

// The real macOS Keychain, under a service name of the test's own, removed
// at the end.
func TestKeychainRoundTrip(t *testing.T) {
	k := keychain{service: "Sneakers-PAM test " + t.Name()}
	const account = "sneakers.example.org"
	t.Cleanup(func() { _ = k.Delete(account) })
	if _, ok, err := k.Get(account); err != nil || ok {
		t.Fatalf("before: %v %v", ok, err)
	}
	token := "snk_u_" + strings.Repeat("Z", 43)
	if err := k.Set(account, token); err != nil {
		t.Fatal(err)
	}
	// A second login replaces the token.
	token2 := "snk_u_" + strings.Repeat("Y", 43)
	if err := k.Set(account, token2); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := k.Get(account); err != nil || !ok || got != token2 {
		t.Fatalf("got %q %v %v", got, ok, err)
	}
	if err := k.Delete(account); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := k.Get(account); err != nil || ok {
		t.Fatalf("after delete: %v %v", ok, err)
	}
	if err := k.Delete(account); err != nil {
		t.Fatalf("deleting what isn't there: %v", err)
	}
}

// Only a token's own characters reach security(1)'s command line, so a
// value can't add a command or an option.
func TestKeychainRefusesAnythingButATokenAndAHost(t *testing.T) {
	k := keychain{service: "Sneakers-PAM test " + t.Name()}
	for _, bad := range []string{"snk_u_a b", "snk_u_a\nadd-generic-password", "snk_u_\"x"} {
		if err := k.Set("sneakers.example.org", bad); err == nil {
			t.Errorf("stored %q", bad)
		}
	}
	if err := k.Set("a b", "snk_u_x"); err == nil {
		t.Error("took an account with a space")
	}
}
