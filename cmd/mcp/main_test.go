// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
)

func TestEnvFallsBackToDefault(t *testing.T) {
	t.Setenv("MCP_TEST_KEY", "")
	if got := env("MCP_TEST_KEY", "fallback"); got != "fallback" {
		t.Fatalf("env() = %q, want \"fallback\"", got)
	}
	t.Setenv("MCP_TEST_KEY", "set")
	if got := env("MCP_TEST_KEY", "fallback"); got != "set" {
		t.Fatalf("env() = %q, want \"set\"", got)
	}
}

func TestLoadConfigHydraMode(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "http://sneakers-hydra:4444/")
	t.Setenv("MCP_RESOURCE_URL", "https://sneakers-mcp.example.org/mcp")
	t.Setenv("MCP_ACCEPT_API_TOKENS", "false")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.hydraEnabled() || cfg.AcceptAPITokens {
		t.Fatalf("modes wrong: %+v", cfg)
	}
	if cfg.HydraAudience != "sneakers-mcp" || cfg.HTTPPort != "9101" {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
}

func TestLoadConfigHydraModeRequiresResourceURL(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "http://sneakers-hydra:4444/")
	t.Setenv("MCP_RESOURCE_URL", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("Hydra mode must refuse to start without MCP_RESOURCE_URL")
	}
}

func TestLoadConfigAPITokensDefaultOn(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "")
	t.Setenv("MCP_RESOURCE_URL", "")
	t.Setenv("MCP_ACCEPT_API_TOKENS", "")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("API-only mode must start without Hydra: %v", err)
	}
	if cfg.hydraEnabled() || !cfg.AcceptAPITokens {
		t.Fatalf("modes wrong: %+v", cfg)
	}
	if cfg.OTLPEndpoint != "" {
		t.Fatalf("default OTLPEndpoint got %q, want empty (no collector)", cfg.OTLPEndpoint)
	}
	if _, err := buildHandler(t.Context(), cfg, zerolog.Nop()); err != nil {
		t.Fatalf("buildHandler in API-only mode: %v", err)
	}
}

func TestLoadConfigNothingConfiguredFails(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "")
	t.Setenv("MCP_ACCEPT_API_TOKENS", "false")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig must refuse to start with no bearer mode")
	}
	// buildHandler must fail closed on its own too, not rely on loadConfig.
	if _, err := buildHandler(t.Context(), config{GatewayURL: "http://gw"}, zerolog.Nop()); err == nil {
		t.Fatal("buildHandler must refuse a config with no bearer mode")
	}
}

func TestLoadConfigRejectsBadBool(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "")
	t.Setenv("MCP_ACCEPT_API_TOKENS", "yes please")
	if _, err := loadConfig(); err == nil {
		t.Fatal("an unparseable MCP_ACCEPT_API_TOKENS must fail, not default")
	}
}

func TestResourceMetadataURL(t *testing.T) {
	got, err := resourceMetadataURL("https://sneakers-mcp.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://sneakers-mcp.example.org/.well-known/oauth-protected-resource/mcp" {
		t.Fatalf("got %q", got)
	}
	if _, err := resourceMetadataURL("not a url"); err == nil {
		t.Fatal("want error for a non-absolute resource URL")
	}
}

// --- end-to-end harness: real JWKS, real MCP stack, fake gateway ---------

const e2eIssuer = "https://hydra.example.org/"

type harness struct {
	key     *rsa.PrivateKey
	srv     *httptest.Server
	gwMu    sync.Mutex
	gwAuths []string // tool-call (non-health) requests
	health  []string // machineHealth pre-check requests
	// validAPITokens are the SA API tokens the fake gateway accepts;
	// gwStatus, when non-zero, overrides every gateway answer.
	validAPITokens map[string]bool
	gwStatus       int
	logs           *lockedBuffer
}

// lockedBuffer is a goroutine-safe log sink: the server logs from its own
// goroutines while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith builds the harness, letting mut adjust the config (e.g. to
// disable Hydra) before the handler is built.
func newHarnessWith(t *testing.T, mut func(*config)) *harness {
	t.Helper()
	h := &harness{logs: &lockedBuffer{}, validAPITokens: map[string]bool{}}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h.key = key
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwks.Close)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The background readiness check of the gateway, not a tool call.
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		authz := r.Header.Get("Authorization")
		h.gwMu.Lock()
		isHealth := strings.Contains(string(body), "machineHealth")
		if isHealth {
			h.health = append(h.health, authz)
		} else {
			h.gwAuths = append(h.gwAuths, authz)
		}
		st := h.gwStatus
		// Mimic MachineActor: an opaque bearer is checked against identity.
		tok := strings.TrimPrefix(authz, "Bearer ")
		opaqueRejected := !strings.Contains(tok, ".") && !h.validAPITokens[tok]
		h.gwMu.Unlock()
		switch {
		case st != 0:
			http.Error(w, "unavailable", st)
		case opaqueRejected:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case isHealth:
			_, _ = io.WriteString(w, `{"data":{"machineHealth":true}}`)
		default:
			_, _ = io.WriteString(w, gatewayReply(string(body)))
		}
	}))
	t.Cleanup(gw.Close)

	cfg := config{
		HTTPPort:      "0",
		HydraIssuer:   e2eIssuer,
		HydraJWKSURL:  jwks.URL,
		HydraAudience: "sneakers-mcp",
		ResourceURL:   "https://mcp.example.org/mcp",
		GatewayURL:    gw.URL,
		Version:       "test",
		// AcceptAPITokens mirrors the production default.
		AcceptAPITokens: true,
	}
	if mut != nil {
		mut(&cfg)
	}
	handler, err := buildHandler(t.Context(), cfg, zerolog.New(h.logs))
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	h.srv = httptest.NewServer(handler)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) token(t *testing.T, sub string, mut func(jwt.MapClaims)) string {
	t.Helper()
	c := jwt.MapClaims{
		"iss": e2eIssuer, "aud": []string{"sneakers-mcp"}, "sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	if mut != nil {
		mut(c)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func (h *harness) connect(t *testing.T, tok string) (*mcp.ClientSession, error) {
	t.Helper()
	tr := &mcp.StreamableClientTransport{
		Endpoint:             h.srv.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerRT{tok: tok}},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(context.Background(), tr, nil)
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

func rawPost(t *testing.T, url, authz string) *http.Response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestLivezIsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	resp, err := http.Get(h.srv.URL + "/livez")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.Status != "ok" {
		t.Fatalf("GET /livez = %d %q", resp.StatusCode, body.Status)
	}
}

func TestMCPRejectsMissingAndInvalidBearerWith401(t *testing.T) {
	h := newHarness(t)
	wrongAud := h.token(t, "client-abc", func(c jwt.MapClaims) { c["aud"] = []string{"sneakers-gateway"} })
	cases := map[string]string{
		"missing":        "",
		"not bearer":     "Basic Zm9vOmJhcg==",
		"garbage":        "Bearer not-a-jwt",
		"wrong audience": "Bearer " + wrongAud,
	}
	for name, authz := range cases {
		t.Run(name, func(t *testing.T) {
			resp := rawPost(t, h.srv.URL+"/mcp", authz)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if wa := resp.Header.Get("WWW-Authenticate"); !strings.Contains(wa, "resource_metadata=") {
				t.Fatalf("WWW-Authenticate = %q, want a resource_metadata pointer", wa)
			}
			b, _ := io.ReadAll(resp.Body)
			if strings.TrimSpace(string(b)) != "invalid token" && name != "missing" && name != "not bearer" {
				t.Fatalf("401 body %q must be opaque (no validation detail)", b)
			}
		})
	}
	h.gwMu.Lock()
	n := len(h.gwAuths)
	h.gwMu.Unlock()
	if n != 0 {
		t.Fatalf("gateway was called %d times by unauthenticated requests", n)
	}
	if strings.Contains(h.logs.String(), wrongAud) {
		t.Fatal("a rejected token was logged")
	}
}

func TestProtectedResourceMetadataIsServed(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(h.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		var md struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&md)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || md.Resource != "https://mcp.example.org/mcp" || len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != e2eIssuer {
			t.Fatalf("GET %s = %d %+v", p, resp.StatusCode, md)
		}
	}
}

func TestEndToEndToolCallForwardsEachCallersOwnToken(t *testing.T) {
	h := newHarness(t)
	tokA := h.token(t, "client-a", nil)
	tokB := h.token(t, "client-b", nil)

	for _, tok := range []string{tokA, tokB, tokA} {
		cs, err := h.connect(t, tok)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "sneakers_get_secret",
			Arguments: map[string]any{"id": "s1", "fieldKey": "password"},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("tool error: %+v", res.Content)
		}
		b, _ := json.Marshal(res.StructuredContent)
		if !strings.Contains(string(b), "REVEALED-VALUE") {
			t.Fatalf("structured content = %s", b)
		}
	}

	// get_secret reads the secret's summary, then the value: two calls each.
	want := []string{"Bearer " + tokA, "Bearer " + tokA, "Bearer " + tokB, "Bearer " + tokB, "Bearer " + tokA, "Bearer " + tokA}
	h.gwMu.Lock()
	defer h.gwMu.Unlock()
	if len(h.gwAuths) != len(want) {
		t.Fatalf("gateway calls = %d, want %d", len(h.gwAuths), len(want))
	}
	for i := range want {
		if h.gwAuths[i] != want[i] {
			t.Fatalf("gateway call %d carried the wrong caller's token", i)
		}
	}
	logs := h.logs.String()
	for _, leak := range []string{tokA, tokB, "REVEALED-VALUE"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("logs leak a token or revealed value: %s", logs)
		}
	}
}

func TestOversizedRequestBodyIsRejected(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "client-a", nil)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("a", maxRequestBodyBytes+1) + `"}}`
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
