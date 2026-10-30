// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"strings"
	"testing"
)

// fakeKeyring is a keyring in memory that may or may not be running.
type fakeKeyring struct {
	running bool
	items   map[string]string
}

func (k *fakeKeyring) Available() bool { return k.running }
func (k *fakeKeyring) Get(account string) (string, bool, error) {
	v, ok := k.items[account]
	return v, ok, nil
}
func (k *fakeKeyring) Set(account, token string) error { k.items[account] = token; return nil }
func (k *fakeKeyring) Delete(account string) error     { delete(k.items, account); return nil }
func (k *fakeKeyring) Where(account string) string     { return "the keyring (" + account + ")" }

var token = "snk_u_" + strings.Repeat("K", 43)

func TestFallbackUsesTheKeyringWhenOneIsRunning(t *testing.T) {
	k := &fakeKeyring{running: true, items: map[string]string{}}
	file := FileStore(t.TempDir())
	s := fallbackStore{keyring: k, file: file}
	if err := s.Set("sneakers.example.org", token); err != nil {
		t.Fatal(err)
	}
	if k.items["sneakers.example.org"] != token {
		t.Fatal("the token isn't in the keyring")
	}
	if _, ok, _ := file.Get("sneakers.example.org"); ok {
		t.Fatal("the token was also written to a file")
	}
	if !strings.Contains(s.Where("sneakers.example.org"), "keyring") {
		t.Fatalf("Where said %q", s.Where("sneakers.example.org"))
	}
}

func TestFallbackUsesAFileWithNoKeyring(t *testing.T) {
	k := &fakeKeyring{items: map[string]string{}}
	file := FileStore(t.TempDir())
	s := fallbackStore{keyring: k, file: file}
	if err := s.Set("sneakers.example.org", token); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := file.Get("sneakers.example.org"); err != nil || !ok || got != token {
		t.Fatalf("file has %q %v %v", got, ok, err)
	}
	if s.Where("sneakers.example.org") != file.Where("sneakers.example.org") {
		t.Fatalf("Where said %q", s.Where("sneakers.example.org"))
	}
	if err := s.Delete("sneakers.example.org"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := file.Get("sneakers.example.org"); ok {
		t.Fatal("logout left the file")
	}
}

// A box signed in headless, then from a desktop session, still finds the file's
// token, and a later login in the keyring removes the file so no stale copy stays.
func TestFallbackMovesFromAFileToTheKeyring(t *testing.T) {
	k := &fakeKeyring{items: map[string]string{}}
	file := FileStore(t.TempDir())
	s := fallbackStore{keyring: k, file: file}
	if err := s.Set("sneakers.example.org", token); err != nil {
		t.Fatal(err)
	}
	k.running = true
	if got, ok, err := s.Get("sneakers.example.org"); err != nil || !ok || got != token {
		t.Fatalf("%q %v %v", got, ok, err)
	}
	if err := s.Set("sneakers.example.org", token); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := file.Get("sneakers.example.org"); ok {
		t.Fatal("the file's copy stayed after the keyring took the token")
	}
	if err := s.Delete("sneakers.example.org"); err != nil {
		t.Fatal(err)
	}
	if len(k.items) != 0 {
		t.Fatal("logout left the keyring's token")
	}
}
