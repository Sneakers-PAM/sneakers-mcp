// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a certificate for the DNS name and returns its PEM pair.
func (ca *testCA) leaf(t *testing.T, dns string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

// writeIdentity writes the cert, key and CA files for a service and sets the
// MTLS_* variables to them.
func writeIdentity(t *testing.T, ca *testCA, dns string) {
	t.Helper()
	dir := t.TempDir()
	c, k := ca.leaf(t, dns)
	for name, data := range map[string][]byte{"tls.crt": c, "tls.key": k, "ca.crt": ca.pem} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("MTLS_CERT_FILE", filepath.Join(dir, "tls.crt"))
	t.Setenv("MTLS_KEY_FILE", filepath.Join(dir, "tls.key"))
	t.Setenv("MTLS_CA_FILE", filepath.Join(dir, "ca.crt"))
}

// mtlsGateway is an mTLS-only stand-in for the gateway's port 9443. Its
// certificate names "localhost", which the client dials.
func mtlsGateway(t *testing.T, ca *testCA, h http.Handler) *httptest.Server {
	t.Helper()
	c, k := ca.leaf(t, "localhost")
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pair}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clearMTLS(t *testing.T) {
	t.Helper()
	for _, v := range []string{"MTLS_CERT_FILE", "MTLS_KEY_FILE", "MTLS_CA_FILE"} {
		t.Setenv(v, "")
	}
}

func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HYDRA_ISSUER", "")
	t.Setenv("MCP_ACCEPT_API_TOKENS", "true")
}

func TestLoadConfigMTLSUnsetIsPlaintext(t *testing.T) {
	baseEnv(t)
	clearMTLS(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.gatewayHTTP != nil {
		t.Fatal("gatewayHTTP is set with no MTLS_* variables; want the plaintext default (nil)")
	}
}

func TestLoadConfigMTLSPartialFailsNamingVariables(t *testing.T) {
	baseEnv(t)
	clearMTLS(t)
	t.Setenv("MTLS_CERT_FILE", "/x/tls.crt")
	_, err := loadConfig()
	if err == nil {
		t.Fatal("a partly set MTLS trio must stop start-up")
	}
	for _, want := range []string{"MTLS_KEY_FILE", "MTLS_CA_FILE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestLoadConfigMTLSUnreadableFileFails(t *testing.T) {
	baseEnv(t)
	t.Setenv("MTLS_CERT_FILE", "/nonexistent/tls.crt")
	t.Setenv("MTLS_KEY_FILE", "/nonexistent/tls.key")
	t.Setenv("MTLS_CA_FILE", "/nonexistent/ca.crt")
	if _, err := loadConfig(); err == nil {
		t.Fatal("unreadable MTLS files must stop start-up")
	}
}

func TestGatewayClientPresentsCertificate(t *testing.T) {
	baseEnv(t)
	ca := newTestCA(t, "cluster")
	writeIdentity(t, ca, "sneakers-mcp")
	var gotCN string
	srv := mtlsGateway(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCN = r.TLS.PeerCertificates[0].Subject.CommonName
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.gatewayHTTP == nil {
		t.Fatal("gatewayHTTP is nil with the MTLS trio set")
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	c := gwclient.New("https://localhost:"+port+"/machine/graphql", cfg.gatewayHTTP)
	_, _ = c.ListSecretTypes(t.Context(), "tok") // the answer is irrelevant; the handshake is the test
	if gotCN != "sneakers-mcp" {
		t.Fatalf("gateway saw client certificate CN %q, want sneakers-mcp", gotCN)
	}
}

func TestGatewayClientRefusesServerFromOtherCA(t *testing.T) {
	baseEnv(t)
	ca := newTestCA(t, "cluster")
	writeIdentity(t, ca, "sneakers-mcp")
	other := newTestCA(t, "other")
	called := false
	srv := mtlsGateway(t, other, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cfg.gatewayHTTP.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a server signed by another CA was accepted")
	}
	if called {
		t.Fatal("the request reached a server the client should not trust")
	}
}

func TestHealthCheckUsesMTLSClient(t *testing.T) {
	baseEnv(t)
	ca := newTestCA(t, "cluster")
	writeIdentity(t, ca, "sneakers-mcp")
	srv := mtlsGateway(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cfg.GatewayURL = "https://localhost:" + port + "/machine/graphql"
	httpc := healthClient(cfg)
	if err := getOK(t.Context(), httpc, originOf(cfg.GatewayURL)+"/readyz"); err != nil {
		t.Fatalf("readiness over mTLS: %v", err)
	}
}
