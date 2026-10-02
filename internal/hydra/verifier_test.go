// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package hydra

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

const (
	testKID      = "test-key-1"
	testIssuer   = "https://hydra.example.org/"
	testAudience = "sneakers-mcp"
)

type jwksServer struct {
	*httptest.Server
	hits atomic.Int32
}

// newJWKSServer serves a single RSA public key as a JWKS document and
// returns the server plus the private key used to sign test tokens.
func newJWKSServer(t *testing.T) (*jwksServer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": testKID,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	js := &jwksServer{}
	js.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(js.Close)
	return js, key
}

func signWith(t *testing.T, key *rsa.PrivateKey, kid string, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func sign(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	return signWith(t, key, testKID, jwt.SigningMethodRS256, claims)
}

func goodClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":   testIssuer,
		"aud":   []string{testAudience},
		"sub":   "client-abc",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "sneakers-secrets mcp-agents",
	}
}

func newTestVerifier(t *testing.T, jwksURL string) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer:   testIssuer,
		JWKSURL:  jwksURL,
		Audience: testAudience,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	cases := map[string]Config{
		"no issuer":   {JWKSURL: "http://x", Audience: "a"},
		"no jwks":     {Issuer: "i", Audience: "a"},
		"no audience": {Issuer: "i", JWKSURL: "http://x"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("New(%s) must fail closed, got nil error", name)
			}
		})
	}
}

func TestVerifyAcceptsValidTokenAndReportsSubjectAndScopes(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	info, err := v.Verify(context.Background(), sign(t, key, goodClaims()), nil)
	if err != nil {
		t.Fatalf("Verify(valid): %v", err)
	}
	if info.UserID != "client-abc" {
		t.Fatalf("UserID = %q, want \"client-abc\"", info.UserID)
	}
	if len(info.Scopes) != 2 || info.Scopes[0] != "sneakers-secrets" || info.Scopes[1] != "mcp-agents" {
		t.Fatalf("Scopes = %v, want [sneakers-secrets mcp-agents]", info.Scopes)
	}
	if info.Expiration.IsZero() {
		t.Fatal("Expiration must be set so the SDK can enforce it")
	}
}

func TestVerifyAcceptsScpArrayClaim(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	c := goodClaims()
	delete(c, "scope")
	c["scp"] = []string{"sneakers-secrets", "mcp-agents"}

	info, err := v.Verify(context.Background(), sign(t, key, c), nil)
	if err != nil {
		t.Fatalf("Verify(scp array): %v", err)
	}
	if len(info.Scopes) != 2 {
		t.Fatalf("Scopes = %v, want 2 entries from the scp array", info.Scopes)
	}
}

func TestVerifyAcceptsStringAudience(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	c := goodClaims()
	c["aud"] = testAudience
	if _, err := v.Verify(context.Background(), sign(t, key, c), nil); err != nil {
		t.Fatalf("Verify(string aud): %v", err)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	expired := goodClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()

	noExp := goodClaims()
	delete(noExp, "exp")

	notYet := goodClaims()
	notYet["nbf"] = time.Now().Add(time.Hour).Unix()

	wrongIss := goodClaims()
	wrongIss["iss"] = "https://evil.example.org/"

	issNoSlash := goodClaims()
	issNoSlash["iss"] = strings.TrimSuffix(testIssuer, "/")

	wrongAud := goodClaims()
	wrongAud["aud"] = []string{"someone-else"}

	noAud := goodClaims()
	delete(noAud, "aud")

	noSub := goodClaims()
	delete(noSub, "sub")

	cases := map[string]string{
		"expired":             sign(t, key, expired),
		"no exp":              sign(t, key, noExp),
		"not yet valid":       sign(t, key, notYet),
		"wrong issuer":        sign(t, key, wrongIss),
		"issuer without /":    sign(t, key, issNoSlash),
		"wrong audience":      sign(t, key, wrongAud),
		"no audience":         sign(t, key, noAud),
		"no subject":          sign(t, key, noSub),
		"unknown kid":         signWith(t, key, "other-kid", jwt.SigningMethodRS256, goodClaims()),
		"alg RS512 not RS256": signWith(t, key, testKID, jwt.SigningMethodRS512, goodClaims()),
		"alg none":            noneToken(t),
		"garbage":             "not-a-jwt",
		"empty":               "",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tok, nil)
			if err == nil {
				t.Fatalf("Verify(%s): want error, got nil", name)
			}
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("Verify(%s): error must wrap auth.ErrInvalidToken so the SDK answers 401, got %v", name, err)
			}
		})
	}
}

func noneToken(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, goodClaims())
	tok.Header["kid"] = testKID
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	return s
}

func TestVerifyRejectsTokenSignedByAnotherKey(t *testing.T) {
	srv, _ := newJWKSServer(t)
	_, otherKey := newJWKSServer(t) // different key, not in the served JWKS
	v := newTestVerifier(t, srv.URL)

	if _, err := v.Verify(context.Background(), sign(t, otherKey, goodClaims()), nil); err == nil {
		t.Fatal("token signed by an unknown key must be rejected")
	}
}

func TestVerifyErrorNeverEchoesTheToken(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	c := goodClaims()
	c["aud"] = []string{"someone-else"}
	tok := sign(t, key, c)
	_, err := v.Verify(context.Background(), tok, nil)
	if err == nil {
		t.Fatal("want error")
	}
	for _, part := range strings.Split(tok, ".") {
		if strings.Contains(err.Error(), part) {
			t.Fatalf("error %q leaks a token segment", err)
		}
	}
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	srv, key := newJWKSServer(t)
	v := newTestVerifier(t, srv.URL)

	// Prime the cache with one good verification.
	if _, err := v.Verify(context.Background(), sign(t, key, goodClaims()), nil); err != nil {
		t.Fatalf("prime: %v", err)
	}
	before := srv.hits.Load()
	for range 20 {
		_, _ = v.Verify(context.Background(), signWith(t, key, "random-kid", jwt.SigningMethodRS256, goodClaims()), nil)
	}
	if got := srv.hits.Load() - before; got > 1 {
		t.Fatalf("unknown kids triggered %d JWKS fetches; want at most 1 inside the refresh interval", got)
	}
}

func TestJWKSOutageFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := newTestVerifier(t, srv.URL)
	if _, err := v.Verify(context.Background(), sign(t, key, goodClaims()), nil); err == nil {
		t.Fatal("with no reachable JWKS every token must be rejected")
	}
}
