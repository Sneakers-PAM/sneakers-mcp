// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

func TestFileStoreKeepsATokenOnlyThisUserCanRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sneakers")
	s := cliauth.FileStore(dir)
	const account = "sneakers.example.org:8443"
	if _, ok, err := s.Get(account); err != nil || ok {
		t.Fatalf("an empty store gave %v %v", ok, err)
	}
	if err := s.Set(account, stored); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "token-"+account)
	if s.Where(account) != path {
		t.Fatalf("Where said %q", s.Where(account))
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v", fi, err)
	}
	if di, err := os.Stat(dir); err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("token folder %v %v", di, err)
	}
	if got, ok, err := s.Get(account); err != nil || !ok || got != stored {
		t.Fatalf("%q %v %v", got, ok, err)
	}
	if err := s.Delete(account); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Delete left the file: %v", err)
	}
	if err := s.Delete(account); err != nil {
		t.Fatalf("deleting no token: %v", err)
	}
}

func TestFileStoreReplacesAToken(t *testing.T) {
	s := cliauth.FileStore(t.TempDir())
	other := "snk_u_" + strings.Repeat("Z", 43)
	if err := s.Set("sneakers.example.org", stored); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("sneakers.example.org", other); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Get("sneakers.example.org"); err != nil || got != other {
		t.Fatalf("%q %v", got, err)
	}
}

// Like ssh with a private key, a token file others can read is refused, not used.
func TestFileStoreRefusesATokenFileOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	s := cliauth.FileStore(dir)
	if err := s.Set("sneakers.example.org", stored); err != nil {
		t.Fatal(err)
	}
	path := s.Where("sneakers.example.org")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Get("sneakers.example.org")
	if err == nil || !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(err.Error(), path) {
		t.Fatalf("got %v", err)
	}
}

func TestFileStoreTakesOnlyAPersonalTokenAndAGatewayHost(t *testing.T) {
	dir := t.TempDir()
	s := cliauth.FileStore(dir)
	if err := s.Set("sneakers.example.org", "snk_sa_x"); err == nil {
		t.Fatal("stored a service token")
	}
	if err := s.Set("../escape", stored); err == nil {
		t.Fatal("took a path as a gateway host")
	}
	if err := os.WriteFile(filepath.Join(dir, "token-sneakers.example.org"), []byte("not a token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get("sneakers.example.org"); err == nil {
		t.Fatal("read something that isn't a personal token")
	}
}
