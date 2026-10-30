// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certkit "github.com/Bugs5382/go-certkit"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

// selfSigned makes a certificate like a new appliance's own: a self-signed
// leaf for localhost that no system trusts.
func selfSigned(t *testing.T) certkit.Bundle {
	t.Helper()
	b, err := certkit.GenerateSelfSigned(certkit.GenOpts{CommonName: "localhost", DNSNames: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startBox starts srv on localhost over HTTPS, presenting b.
func startBox(t *testing.T, srv *httptest.Server, b certkit.Bundle) {
	t.Helper()
	pair, err := tls.X509KeyPair(b.LeafPEM, b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	srv.URL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
}

// boxServer is an HTTPS server on localhost that presents b.
func boxServer(t *testing.T, b certkit.Bundle, h http.Handler) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	startBox(t, srv, b)
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "box.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func get(t *testing.T, hc *http.Client, u string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func TestHTTPClientTrustsTheBoxCertificateOnlyWhenGiven(t *testing.T) {
	box := selfSigned(t)
	u := boxServer(t, box, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	plain, err := cliauth.HTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	var unknown x509.UnknownAuthorityError
	if err := get(t, plain, u); !errors.As(err, &unknown) {
		t.Fatalf("without the file: %v", err)
	}

	trusted, err := cliauth.HTTPClient(writeFile(t, box.LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, trusted, u); err != nil {
		t.Fatalf("with the box's certificate: %v", err)
	}

	wrong, err := cliauth.HTTPClient(writeFile(t, selfSigned(t).LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, wrong, u); err == nil {
		t.Fatal("trusted the box with another certificate")
	}
}

func TestHTTPClientKeepsTheSystemRootsAndTheHostCheck(t *testing.T) {
	box := selfSigned(t)
	u := boxServer(t, box, http.NotFoundHandler())
	hc, err := cliauth.HTTPClient(writeFile(t, box.LeafPEM))
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("transport %#v", hc.Transport)
	}
	if hc.Timeout == 0 {
		t.Fatal("no timeout")
	}
	// The certificate names localhost; the same server reached as 127.0.0.1
	// must still fail the name check.
	if err := get(t, hc, strings.Replace(u, "localhost", "127.0.0.1", 1)); err == nil {
		t.Fatal("the host name wasn't checked")
	}
}

func TestHTTPClientRefusesABadFile(t *testing.T) {
	box := selfSigned(t)
	cases := map[string]string{
		"missing":     filepath.Join(t.TempDir(), "none.pem"),
		"not pem":     writeFile(t, []byte("not a certificate\n")),
		"empty":       writeFile(t, nil),
		"key only":    writeFile(t, box.KeyPEM),
		"with a key":  writeFile(t, append(append([]byte{}, box.LeafPEM...), box.KeyPEM...)),
		"broken cert": writeFile(t, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")),
	}
	for name, p := range cases {
		hc, err := cliauth.HTTPClient(p)
		if err == nil {
			t.Errorf("%s: accepted (%v)", name, hc)
			continue
		}
		if !strings.Contains(err.Error(), cliauth.CAFileEnv) {
			t.Errorf("%s: %v doesn't name %s", name, err, cliauth.CAFileEnv)
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), string(box.KeyPEM[40:80])) {
			t.Errorf("%s: the error quotes the file: %v", name, err)
		}
	}
}

func TestHTTPClientTakesSeveralRoots(t *testing.T) {
	box := selfSigned(t)
	u := boxServer(t, box, http.NotFoundHandler())
	pemFile := append(append([]byte{}, selfSigned(t).LeafPEM...), box.LeafPEM...)
	hc, err := cliauth.HTTPClient(writeFile(t, pemFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, hc, u); err != nil {
		t.Fatalf("the second certificate in the file wasn't trusted: %v", err)
	}
}

func TestCAFileFlagWinsOverTheEnvironment(t *testing.T) {
	getenv := env(map[string]string{cliauth.CAFileEnv: "/env.pem"})
	if got := cliauth.CAFile("/flag.pem", getenv); got != "/flag.pem" {
		t.Fatalf("got %q", got)
	}
	if got := cliauth.CAFile("", getenv); got != "/env.pem" {
		t.Fatalf("got %q", got)
	}
}

func TestLoginTrustsTheBoxCertificate(t *testing.T) {
	box := selfSigned(t)
	g := newTLSGateway(t, box)
	store := memStore{}
	var stdout, stderr strings.Builder
	s := session(t, g, store, &stdout, &stderr)
	caFile := writeFile(t, box.LeafPEM)
	trusting, err := cliauth.HTTPClient(caFile)
	if err != nil {
		t.Fatal(err)
	}
	var opened string
	s.Opener = func() func(string) { return browserWith(t, trusting, &opened) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := cliauth.RunAuth(ctx, s, []string{"login"}); code == 0 || opened != "" {
		t.Fatalf("signed in to an untrusted box (opened %q)", opened)
	}
	if code := cliauth.RunAuth(ctx, s, []string{"login", "-ca-file", caFile}); code != 0 {
		t.Fatalf("login with -ca-file: %d %s", code, readSync(&stderr))
	}
	account, _ := cliauth.Account(g.srv.URL)
	if store[account] != g.token {
		t.Fatalf("stored %v", store)
	}
}
