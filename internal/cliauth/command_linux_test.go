// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cliauth_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

// secretServiceUnderTest is set by CI's Linux job when it runs the tests in a
// D-Bus session with an unlocked keyring; otherwise the tests never reach a
// person's real keyring.
func secretServiceUnderTest() bool { return os.Getenv("SNEAKERS_TEST_SECRET_SERVICE") == "1" }

// Login and logout through this system's own store, against the fake gateway:
// the keyring when CI runs one, else a 0600 file under XDG_CONFIG_HOME.
func TestLinuxLoginStoresTheTokenAndLogoutRemovesIt(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	if !secretServiceUnderTest() {
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	}
	store := cliauth.DefaultStore()
	if store == nil {
		t.Fatal("no store on Linux")
	}
	g := newGateway(t)
	var stdout, stderr strings.Builder
	s := session(t, g, store, &stdout, &stderr)
	if code := cliauth.RunAuth(context.Background(), s, []string{"login", "-insecure-localhost"}); code != 0 {
		t.Fatalf("login: %d %s", code, readSync(&stderr))
	}
	g.landedOn(t)
	account, _ := cliauth.Account(g.srv.URL)
	file := filepath.Join(config, "sneakers", "token-"+account)
	checkStoredWhereItSaid(t, stdout.String(), file)
	if strings.Contains(stdout.String(), g.token) || strings.Contains(readSync(&stderr), g.token) {
		t.Fatal("the token was printed")
	}
	_, token, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": g.srv.URL}), true, store)
	if err != nil || token != g.token {
		t.Fatalf("%q %v", token, err)
	}
	if code := cliauth.RunAuth(context.Background(), s, []string{"logout", "-insecure-localhost"}); code != 0 {
		t.Fatalf("logout: %d %s", code, readSync(&stderr))
	}
	if _, ok, err := store.Get(account); err != nil || ok {
		t.Fatalf("logout left the token: %v %v", ok, err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("logout left the file: %v", err)
	}
}

// checkStoredWhereItSaid checks login named where the token went, and that
// it's only there: the keyring with no file, or a 0600 file.
func checkStoredWhereItSaid(t *testing.T, said, file string) {
	t.Helper()
	if secretServiceUnderTest() {
		if !strings.Contains(said, "Secret Service keyring") {
			t.Fatalf("login said %q", said)
		}
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("a token file was written next to the keyring: %v", err)
		}
		return
	}
	if !strings.Contains(said, file) {
		t.Fatalf("login didn't say where the token is: %q", said)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v", fi, err)
	}
}
