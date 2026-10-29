// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

func session(t *testing.T, g *gateway, store cliauth.Store, stdout, stderr *strings.Builder) cliauth.Session {
	var opened string
	return cliauth.Session{
		Prog: "sneakers-put", Getenv: env(map[string]string{"SNEAKERS_URL": g.srv.URL}), Store: store,
		Opener: func() func(string) { return browser(t, &opened) }, Stdout: stdout, Stderr: &syncWriter{w: stderr},
		HostName: func() (string, error) { return "laptop-01", nil },
	}
}

func TestLoginStoresTheTokenAndLogoutRemovesIt(t *testing.T) {
	g := newGateway(t)
	store := memStore{}
	var stdout, stderr strings.Builder
	s := session(t, g, store, &stdout, &stderr)
	if code := cliauth.RunAuth(context.Background(), s, []string{"login", "-insecure-localhost"}); code != 0 {
		t.Fatalf("login: %d %s", code, readSync(&stderr))
	}
	account, _ := cliauth.Account(g.srv.URL)
	if store[account] != g.token || g.clientName != "sneakers-put on laptop-01" {
		t.Fatalf("stored %v, client %q", store, g.clientName)
	}
	if strings.Contains(stdout.String(), g.token) || strings.Contains(readSync(&stderr), g.token) {
		t.Fatal("the token was printed")
	}
	// What login stored is what the commands then use.
	_, token, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": g.srv.URL}), true, store)
	if err != nil || token != g.token {
		t.Fatalf("%q %v", token, err)
	}
	if code := cliauth.RunAuth(context.Background(), s, []string{"logout", "-insecure-localhost"}); code != 0 {
		t.Fatalf("logout: %d %s", code, readSync(&stderr))
	}
	if _, ok := store[account]; ok {
		t.Fatal("logout left the token")
	}
}

func TestLoginNeedsAStoreAndAnHTTPSGateway(t *testing.T) {
	g := newGateway(t)
	var stdout, stderr strings.Builder
	s := session(t, g, nil, &stdout, &stderr)
	if code := cliauth.RunAuth(context.Background(), s, []string{"login", "-insecure-localhost"}); code == 0 || !strings.Contains(readSync(&stderr), "Keychain") {
		t.Fatalf("logged in with no store: %s", readSync(&stderr))
	}
	s = session(t, g, memStore{}, &stdout, &stderr)
	if code := cliauth.RunAuth(context.Background(), s, []string{"login"}); code == 0 {
		t.Fatal("logged in to an http gateway without -insecure-localhost")
	}
	if g.exchanged != 0 {
		t.Fatal("a refused login reached the gateway")
	}
}

func TestIsAuth(t *testing.T) {
	if !cliauth.IsAuth([]string{"login"}) || !cliauth.IsAuth([]string{"logout"}) || cliauth.IsAuth([]string{"-id", "login"}) || cliauth.IsAuth(nil) {
		t.Fatal("IsAuth")
	}
}
