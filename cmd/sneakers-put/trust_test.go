// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	certkit "github.com/Bugs5382/go-certkit"
)

// boxGateway is the fake gateway over HTTPS on localhost with a self-signed
// certificate, as a new appliance serves it, and the PEM file of that
// certificate.
func boxGateway(t *testing.T, calls *atomic.Int32) (url, caFile string) {
	t.Helper()
	box, err := certkit.GenerateSelfSigned(certkit.GenOpts{CommonName: "localhost", DNSNames: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(box.LeafPEM, box.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f1","typeId":"t"},"changedFieldKeys":["password"]}}}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "box.pem")
	if err := os.WriteFile(caFile, box.LeafPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), caFile
}

func TestRunTrustsTheBoxCertificateFromTheFlagOrTheEnvironment(t *testing.T) {
	var calls atomic.Int32
	u, caFile := boxGateway(t, &calls)
	args := []string{"-id", "s1", "-field", "password=-"}
	runWith := func(extra []string, e map[string]string) (int, string) {
		e["SNEAKERS_TOKEN"], e["SNEAKERS_URL"] = "snk_u_x", u
		var stdout, stderr bytes.Buffer
		code := run(append(extra, args...), env(e), strings.NewReader("v"), &stdout, &stderr)
		return code, stderr.String()
	}
	if code, stderr := runWith(nil, map[string]string{}); code == 0 || !strings.Contains(stderr, "certificate") {
		t.Fatalf("untrusted box: exit %d %s", code, stderr)
	}
	if code, stderr := runWith([]string{"-ca-file", caFile}, map[string]string{}); code != 0 {
		t.Fatalf("-ca-file: exit %d %s", code, stderr)
	}
	if code, stderr := runWith(nil, map[string]string{"SNEAKERS_CA_FILE": caFile}); code != 0 {
		t.Fatalf("SNEAKERS_CA_FILE: exit %d %s", code, stderr)
	}
	if calls.Load() != 2 {
		t.Fatalf("the gateway answered %d calls", calls.Load())
	}
}

func TestRunRefusesABadCAFileBeforeAnyRequest(t *testing.T) {
	var calls atomic.Int32
	u, _ := boxGateway(t, &calls)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-ca-file", bad, "-id", "s1", "-field", "password=-"},
		env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": u}), strings.NewReader("v"), &stdout, &stderr)
	if code != 2 || calls.Load() != 0 || !strings.Contains(stderr.String(), "SNEAKERS_CA_FILE") {
		t.Fatalf("exit %d calls %d stderr %s", code, calls.Load(), stderr.String())
	}
}
