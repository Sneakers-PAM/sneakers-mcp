// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// saToken mints a token in identity's exact format (base64url of 32 bytes).
func saToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func apiOnly(c *config) {
	c.HydraIssuer = ""
	c.HydraJWKSURL = ""
	c.AcceptAPITokens = true
}

func (h *harness) allow(tok string) {
	h.gwMu.Lock()
	defer h.gwMu.Unlock()
	h.validAPITokens[tok] = true
}

func (h *harness) revoke(tok string) {
	h.gwMu.Lock()
	defer h.gwMu.Unlock()
	delete(h.validAPITokens, tok)
}

func (h *harness) counts() (tool, health int) {
	h.gwMu.Lock()
	defer h.gwMu.Unlock()
	return len(h.gwAuths), len(h.health)
}

func expect401(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(b)) != "invalid token" {
		t.Fatalf("401 body %q must be the generic \"invalid token\"", b)
	}
}

func TestAPITokenGoodEndToEnd(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	tok := saToken(t)
	h.allow(tok)

	cs, err := h.connect(t, tok)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "sneakers_get_secret",
		Arguments: map[string]any{"id": "s1", "fieldKey": "password"},
	})
	if err != nil || res.IsError {
		t.Fatalf("CallTool: %v %+v", err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if !strings.Contains(string(b), "REVEALED-VALUE") {
		t.Fatalf("structured content = %s", b)
	}

	h.gwMu.Lock()
	defer h.gwMu.Unlock()
	if len(h.gwAuths) != 1 || h.gwAuths[0] != "Bearer "+tok {
		t.Fatalf("tool call must forward the caller's token unchanged, got %v", h.gwAuths)
	}
	// initialize + notifications + tools/call arrive as separate POSTs;
	// the positive cache means the gateway was pre-checked only once.
	if len(h.health) != 1 {
		t.Fatalf("machineHealth pre-checks = %d, want 1 (cached)", len(h.health))
	}
	if logs := h.logs.String(); strings.Contains(logs, tok) || strings.Contains(logs, "REVEALED-VALUE") {
		t.Fatalf("logs leak the token or value: %s", logs)
	}
}

func TestAPITokenBadIs401AndNoToolCall(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	tok := saToken(t) // well-formed but unknown to the gateway
	expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+tok))
	if tool, health := h.counts(); tool != 0 || health != 1 {
		t.Fatalf("tool calls = %d (want 0), pre-checks = %d (want 1)", tool, health)
	}
	if strings.Contains(h.logs.String(), tok) {
		t.Fatal("a rejected API token was logged")
	}
}

func TestAPITokenRevokedIs401(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	tok := saToken(t)
	h.allow(tok)
	if resp := rawPost(t, h.srv.URL+"/mcp", "Bearer "+tok); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token: status %d", resp.StatusCode)
	}
	h.revoke(tok)
	// The edge cache may still admit the request for <=TTL, but the tool
	// call itself is re-authenticated by the gateway and must fail.
	cs, err := h.connect(t, tok)
	if err == nil {
		res, cerr := cs.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "sneakers_get_secret",
			Arguments: map[string]any{"id": "s1", "fieldKey": "password"},
		})
		if cerr == nil && !res.IsError {
			t.Fatal("a revoked token completed a tool call")
		}
		b, _ := json.Marshal(res)
		if strings.Contains(string(b), "REVEALED-VALUE") {
			t.Fatal("a revoked token revealed a value")
		}
	}
	// A fresh verifier (no cache) rejects it at the edge.
	h2 := newHarnessWith(t, apiOnly)
	expect401(t, rawPost(t, h2.srv.URL+"/mcp", "Bearer "+tok))
}

func TestAPITokenGatewayDownFailsClosed(t *testing.T) {
	for _, st := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		h := newHarnessWith(t, apiOnly)
		tok := saToken(t)
		h.allow(tok)
		h.gwMu.Lock()
		h.gwStatus = st
		h.gwMu.Unlock()
		expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+tok))
		if tool, _ := h.counts(); tool != 0 {
			t.Fatalf("gateway %d: tool call reached the gateway", st)
		}
	}
	// Gateway unreachable altogether.
	h := newHarnessWith(t, func(c *config) { apiOnly(c); c.GatewayURL = "http://127.0.0.1:1/machine/graphql" })
	expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+saToken(t)))
}

func TestMalformedBearerIs401WithoutGatewayContact(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	good := saToken(t)
	for _, bad := range []string{
		"x",
		good[:42],
		good + "A",
		strings.Repeat("+", 43),
		"not.a.jwt",
		strings.Repeat("A", 42) + "B", // non-canonical base64
	} {
		expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+bad))
	}
	if tool, health := h.counts(); tool != 0 || health != 0 {
		t.Fatalf("malformed bearers reached the gateway (tool=%d health=%d)", tool, health)
	}
}

func TestJWTWhenHydraDisabledIs401(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	jwtTok := h.token(t, "client-a", nil) // a genuinely valid RS256 JWT
	expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+jwtTok))
	if tool, health := h.counts(); tool != 0 || health != 0 {
		t.Fatal("a JWT with Hydra disabled must not reach the gateway")
	}
	if strings.Contains(h.logs.String(), jwtTok) {
		t.Fatal("a rejected JWT was logged")
	}
}

func TestAPITokenDisabledRejectsAPITokens(t *testing.T) {
	h := newHarnessWith(t, func(c *config) { c.AcceptAPITokens = false })
	tok := saToken(t)
	h.allow(tok)
	expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer "+tok))
	if tool, health := h.counts(); tool != 0 || health != 0 {
		t.Fatal("API tokens disabled, but the gateway was consulted")
	}
}

func TestMetadataOmitsHydraInAPIOnlyMode(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	resp, err := http.Get(h.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var md map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&md)
	if resp.StatusCode != http.StatusOK || md["resource"] != "https://mcp.example.org/mcp" {
		t.Fatalf("metadata = %d %v", resp.StatusCode, md)
	}
	if _, ok := md["authorization_servers"]; ok {
		t.Fatalf("API-only metadata must not advertise an authorization server: %v", md)
	}

	// Without MCP_RESOURCE_URL there is no metadata at all.
	h2 := newHarnessWith(t, func(c *config) { apiOnly(c); c.ResourceURL = "" })
	r2, err := http.Get(h2.srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("metadata without a resource URL = %d, want 404", r2.StatusCode)
	}
	resp401 := rawPost(t, h2.srv.URL+"/mcp", "Bearer "+saToken(t))
	if wa := resp401.Header.Get("WWW-Authenticate"); strings.Contains(wa, "resource_metadata") {
		t.Fatalf("WWW-Authenticate points at metadata that does not exist: %q", wa)
	}
}
