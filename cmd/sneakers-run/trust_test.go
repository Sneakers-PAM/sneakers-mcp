// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	certkit "github.com/Bugs5382/go-certkit"
)

func TestParseTakesTheCAFile(t *testing.T) {
	box, err := certkit.GenerateSelfSigned(certkit.GenOpts{CommonName: "localhost", DNSNames: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "box.pem"), filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(good, box.LeafPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, box.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	base := map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://localhost:8443"}
	with := func(k, v string) map[string]string {
		m := map[string]string{k: v}
		for a, b := range base {
			m[a] = b
		}
		return m
	}
	cmd := []string{"-secret", "s1", "--", "true"}
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"flag": {append([]string{"-ca-file", good}, cmd...), base},
		"env":  {cmd, with("SNEAKERS_CA_FILE", good)},
	} {
		c, err := parse(tc.args, env(tc.env))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tr, ok := c.hc.Transport.(*http.Transport); !ok || tr.TLSClientConfig.RootCAs == nil || tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("%s: transport %#v", name, c.hc.Transport)
		}
	}
	if _, err := parse(cmd, env(with("SNEAKERS_CA_FILE", bad))); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("a key file: %v", err)
	}
}
