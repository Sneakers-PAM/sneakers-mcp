// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

// memStore is a Store in memory.
type memStore map[string]string

func (m memStore) Get(account string) (string, bool, error) { v, ok := m[account]; return v, ok, nil }
func (m memStore) Set(account, token string) error          { m[account] = token; return nil }
func (m memStore) Delete(account string) error              { delete(m, account); return nil }

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var stored = "snk_u_" + strings.Repeat("K", 43)

func TestResolveTakesTheEnvironmentFirstThenTheStore(t *testing.T) {
	store := memStore{"sneakers.example.org": stored}
	_, token, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org/", "SNEAKERS_TOKEN": "snk_u_env"}), false, store)
	if err != nil || token != "snk_u_env" {
		t.Fatalf("%q %v", token, err)
	}
	endpoint, token, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org"}), false, store)
	if err != nil || token != stored || endpoint != "https://sneakers.example.org/machine/graphql" {
		t.Fatalf("%q %q %v", endpoint, token, err)
	}
}

// The store keeps one token per gateway: another gateway's isn't sent.
func TestResolveKeysTheStoreByTheGatewayHost(t *testing.T) {
	store := memStore{"sneakers.example.org": stored}
	_, _, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://other.example.org"}), false, store)
	if err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveWithNoTokenSaysToLogIn(t *testing.T) {
	for name, store := range map[string]cliauth.Store{"empty store": memStore{}, "no store": nil} {
		_, _, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org"}), false, store)
		if err == nil || !strings.Contains(err.Error(), "login") || !strings.Contains(err.Error(), "SNEAKERS_TOKEN") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestResolveStillRefusesAServiceToken(t *testing.T) {
	store := memStore{"sneakers.example.org": "snk_sa_x"}
	if _, _, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org"}), false, store); err == nil {
		t.Fatal("a stored service token was taken")
	}
	if _, _, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org", "SNEAKERS_TOKEN": "snk_sa_x"}), false, memStore{}); err == nil {
		t.Fatal("a service token in the environment was taken")
	}
}

type brokenStore struct{}

func (brokenStore) Get(string) (string, bool, error) { return "", false, errors.New("keychain locked") }
func (brokenStore) Set(string, string) error         { return nil }
func (brokenStore) Delete(string) error              { return nil }

func TestResolveSaysWhenTheStoreFails(t *testing.T) {
	_, _, err := cliauth.Resolve(env(map[string]string{"SNEAKERS_URL": "https://sneakers.example.org"}), false, brokenStore{})
	if err == nil || !strings.Contains(err.Error(), "keychain locked") {
		t.Fatalf("got %v", err)
	}
}

func TestAccountIsTheGatewayHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://sneakers.example.org/":     "sneakers.example.org",
		"https://Sneakers.Example.org:8443": "sneakers.example.org:8443",
		"http://127.0.0.1:8080":             "127.0.0.1:8080",
	} {
		if got, err := cliauth.Account(in); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
}
