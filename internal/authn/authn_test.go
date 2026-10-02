// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// newToken mints a token exactly as identity's randomToken does: 32
// crypto/rand bytes, base64url without padding.
func newToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestClassify(t *testing.T) {
	good := newToken(t)
	rs256 := b64(`{"alg":"RS256","kid":"k1","typ":"JWT"}`) + "." + b64(`{"sub":"x"}`) + "." + b64("sig")
	cases := map[string]struct {
		in   string
		want Kind
	}{
		"api token":              {good, KindAPIToken},
		"user token":             {"snk_u_" + good, KindAPIToken},
		"user token bad body":    {"snk_u_" + good[:42], KindInvalid},
		"user token prefix only": {"snk_u_", KindInvalid},
		"api token all dashes":   {strings.Repeat("-", 42) + "A", KindAPIToken},
		"rs256 jwt":              {rs256, KindJWT},
		"empty":                  {"", KindInvalid},
		"api token too short":    {good[:42], KindInvalid},
		"api token too long":     {good + "A", KindInvalid},
		"api token padded":       {good + "=", KindInvalid},
		"std base64 chars":       {strings.Repeat("+", 42) + "A", KindInvalid},
		"non-canonical last bit": {strings.Repeat("A", 42) + "B", KindInvalid},
		"whitespace":             {" " + good[1:], KindInvalid},
		"hs256 jwt":              {b64(`{"alg":"HS256"}`) + "." + b64(`{}`) + "." + b64("s"), KindInvalid},
		"alg none jwt":           {b64(`{"alg":"none"}`) + "." + b64(`{}`) + ".", KindInvalid},
		"jwt bad header json":    {b64(`not json`) + "." + b64(`{}`) + "." + b64("s"), KindInvalid},
		"jwt non-b64 segment":    {b64(`{"alg":"RS256"}`) + ".@@." + b64("s"), KindInvalid},
		"two segments":           {b64(`{"alg":"RS256"}`) + "." + b64(`{}`), KindInvalid},
		"four segments":          {rs256 + "." + b64("x"), KindInvalid},
		"garbage":                {"not-a-jwt", KindInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Classify(c.in); got != c.want {
				t.Fatalf("Classify(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// fakeGateway answers machineHealth. status is the HTTP status to return;
// body overrides the 200 body.
type fakeGateway struct {
	mu     sync.Mutex
	status int
	body   string
	calls  atomic.Int32
	auths  []string
	srv    *httptest.Server
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{status: http.StatusOK, body: `{"data":{"machineHealth":true}}`}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "machineHealth") {
			t.Errorf("pre-check sent an unexpected query: %s", b)
		}
		g.mu.Lock()
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		st, body := g.status, g.body
		g.mu.Unlock()
		if st != http.StatusOK {
			http.Error(w, "unauthorized", st)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) set(status int, body string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = status
	if body != "" {
		g.body = body
	}
}

func newVerifier(t *testing.T, url string, now func() time.Time) *APITokenVerifier {
	t.Helper()
	v, err := NewAPITokenVerifier(APITokenConfig{GatewayURL: url, TTL: 30 * time.Second, now: now})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestNewAPITokenVerifierValidatesConfig(t *testing.T) {
	if _, err := NewAPITokenVerifier(APITokenConfig{}); err == nil {
		t.Fatal("want error without a gateway URL")
	}
	if _, err := NewAPITokenVerifier(APITokenConfig{GatewayURL: "http://gw", TTL: 61 * time.Second}); err == nil {
		t.Fatal("want error for a cache TTL above 60s")
	}
	v, err := NewAPITokenVerifier(APITokenConfig{GatewayURL: "http://gw"})
	if err != nil {
		t.Fatal(err)
	}
	if v.ttl <= 0 || v.ttl > 60*time.Second {
		t.Fatalf("default ttl = %v", v.ttl)
	}
}

func TestAPITokenGoodIsAcceptedAndForwardedUnchanged(t *testing.T) {
	g := newFakeGateway(t)
	v := newVerifier(t, g.srv.URL, nil)
	tok := newToken(t)
	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.UserID == "" || strings.Contains(info.UserID, tok) {
		t.Fatalf("UserID %q must be a non-empty, non-secret label", info.UserID)
	}
	if info.Expiration.IsZero() {
		t.Fatal("Expiration must be set (the SDK middleware requires it)")
	}
	if len(g.auths) != 1 || g.auths[0] != "Bearer "+tok {
		t.Fatalf("gateway saw %v, want the caller's own bearer", g.auths)
	}
}

func TestAPITokenRejectedByGatewayIs401(t *testing.T) {
	for _, st := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		g := newFakeGateway(t)
		g.set(st, "")
		v := newVerifier(t, g.srv.URL, nil)
		_, err := v.Verify(context.Background(), newToken(t))
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("status %d: err = %v, want ErrInvalidToken", st, err)
		}
		// Negative results are never cached: each attempt asks the gateway.
		_, _ = v.Verify(context.Background(), newToken(t))
		if g.calls.Load() != 2 {
			t.Fatalf("gateway calls = %d, want 2", g.calls.Load())
		}
	}
}

func TestAPITokenRevokedIsRejectedOnceCacheExpires(t *testing.T) {
	g := newFakeGateway(t)
	c := &clock{t: time.Unix(1_000_000, 0)}
	v := newVerifier(t, g.srv.URL, c.now)
	tok := newToken(t)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	g.set(http.StatusUnauthorized, "") // admin revokes the token
	c.add(10 * time.Second)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("within TTL the cached positive result applies: %v", err)
	}
	if g.calls.Load() != 1 {
		t.Fatalf("cache miss within TTL: gateway calls = %d", g.calls.Load())
	}
	c.add(21 * time.Second)
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("after TTL a revoked token must be rejected, got %v", err)
	}
	if g.calls.Load() != 2 {
		t.Fatalf("gateway calls = %d, want 2", g.calls.Load())
	}
	// The rejection evicted the entry: still rejected, asks again.
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token accepted again: %v", err)
	}
}

func TestAPITokenGatewayFailuresFailClosed(t *testing.T) {
	cases := map[string]func(g *fakeGateway){
		"5xx":             func(g *fakeGateway) { g.set(http.StatusBadGateway, "") },
		"500":             func(g *fakeGateway) { g.set(http.StatusInternalServerError, "") },
		"graphql errors":  func(g *fakeGateway) { g.set(http.StatusOK, `{"errors":[{"message":"boom"}]}`) },
		"health false":    func(g *fakeGateway) { g.set(http.StatusOK, `{"data":{"machineHealth":false}}`) },
		"not json":        func(g *fakeGateway) { g.set(http.StatusOK, `<html>`) },
		"missing field":   func(g *fakeGateway) { g.set(http.StatusOK, `{"data":{}}`) },
		"redirect status": func(g *fakeGateway) { g.set(http.StatusFound, "") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			mut(g)
			v := newVerifier(t, g.srv.URL, nil)
			tok := newToken(t)
			_, err := v.Verify(context.Background(), tok)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("err = %v, want fail-closed ErrInvalidToken", err)
			}
			if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "boom") {
				t.Fatalf("error text leaks token or gateway detail: %v", err)
			}
		})
	}
}

func TestAPITokenGatewayDownFailsClosed(t *testing.T) {
	g := newFakeGateway(t)
	url := g.srv.URL
	g.srv.Close()
	v := newVerifier(t, url, nil)
	tok := newToken(t)
	_, err := v.Verify(context.Background(), tok)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("err = %v, want fail-closed ErrInvalidToken", err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatal("error text leaks the token")
	}
}

func TestAPITokenCacheIsKeyedBySHA256Only(t *testing.T) {
	g := newFakeGateway(t)
	v := newVerifier(t, g.srv.URL, nil)
	tok := newToken(t)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) != 1 {
		t.Fatalf("cache entries = %d, want 1", len(v.cache))
	}
	want := sha256.Sum256([]byte(tok))
	for k := range v.cache {
		if k != want {
			t.Fatal("cache key is not the SHA-256 of the token")
		}
		if strings.Contains(string(k[:]), tok) {
			t.Fatal("cache key contains the raw token")
		}
	}
}

func TestAPITokenCacheIsBounded(t *testing.T) {
	g := newFakeGateway(t)
	v, err := NewAPITokenVerifier(APITokenConfig{GatewayURL: g.srv.URL, MaxEntries: 3})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := v.Verify(context.Background(), newToken(t)); err != nil {
			t.Fatal(err)
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) > 3 {
		t.Fatalf("cache grew to %d entries, cap is 3", len(v.cache))
	}
}

func TestAPITokenVerifierRefusesMalformedWithoutNetwork(t *testing.T) {
	g := newFakeGateway(t)
	v := newVerifier(t, g.srv.URL, nil)
	for _, bad := range []string{"", "short", "a.b.c", newToken(t) + "x"} {
		if _, err := v.Verify(context.Background(), bad); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("Verify(%q) = %v, want ErrInvalidToken", bad, err)
		}
	}
	if g.calls.Load() != 0 {
		t.Fatalf("malformed tokens reached the gateway %d times", g.calls.Load())
	}
}

// --- composite verifier -------------------------------------------------

func TestVerifierDispatch(t *testing.T) {
	g := newFakeGateway(t)
	apiV := newVerifier(t, g.srv.URL, nil)
	jwtCalls := 0
	jwtV := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		jwtCalls++
		return &auth.TokenInfo{UserID: "jwt-sub", Expiration: time.Now().Add(time.Hour)}, nil
	}
	rs256 := b64(`{"alg":"RS256","kid":"k1"}`) + "." + b64(`{"sub":"x"}`) + "." + b64("sig")
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	both := (&Verifier{JWT: jwtV, APIToken: apiV}).TokenVerifier()
	if info, err := both(context.Background(), rs256, req); err != nil || info.UserID != "jwt-sub" {
		t.Fatalf("JWT path: %v %v", info, err)
	}
	if _, err := both(context.Background(), newToken(t), req); err != nil {
		t.Fatalf("API token path: %v", err)
	}
	if _, err := both(context.Background(), "garbage", req); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("garbage: %v", err)
	}

	apiOnly := (&Verifier{APIToken: apiV}).TokenVerifier()
	before := jwtCalls
	if _, err := apiOnly(context.Background(), rs256, req); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("JWT with Hydra disabled must be 401, got %v", err)
	}
	if jwtCalls != before {
		t.Fatal("JWT verifier consulted while disabled")
	}

	gwBefore := g.calls.Load()
	jwtOnly := (&Verifier{JWT: jwtV}).TokenVerifier()
	if _, err := jwtOnly(context.Background(), newToken(t), req); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("API token with API tokens disabled must be 401, got %v", err)
	}
	if g.calls.Load() != gwBefore {
		t.Fatal("gateway consulted while API tokens are disabled")
	}
}

func TestVerifierRequiresAMode(t *testing.T) {
	if (&Verifier{}).Enabled() {
		t.Fatal("a verifier with no mode must report disabled")
	}
}
