// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

// paddingGateway records the last fields sent and reveals a set value.
type paddingGateway struct {
	mu     sync.Mutex
	fields []gwclient.Field
	reveal string
}

func (g *paddingGateway) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string `json:"query"`
			Variables struct {
				Fields []gwclient.Field `json:"fields"`
			} `json:"variables"`
		}
		_ = json.Unmarshal(b, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "createSecretForPrincipal"):
			g.fields = req.Variables.Fields
			_, _ = io.WriteString(w, `{"data":{"createSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f1","typeId":"t1"}}}`)
		case strings.Contains(req.Query, "revealSecretFieldForPrincipal"):
			enc, _ := json.Marshal(g.reveal)
			_, _ = io.WriteString(w, `{"data":{"revealSecretFieldForPrincipal":`+string(enc)+`}}`)
		default:
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

type bearerTransport struct{}

func (bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer agent-tok")
	return http.DefaultTransport.RoundTrip(r)
}

// mcpSession drives the registered tools over real Streamable HTTP, so the
// JSON argument decode and the result encode are both on the path under test.
func mcpSession(t *testing.T, gwURL string) *mcp.ClientSession {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Register(s, gwclient.New(gwURL, nil), zerolog.Nop())
	accept := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{UserID: "client-abc", Expiration: time.Now().Add(time.Hour)}, nil
	}
	h := auth.RequireBearerToken(accept, nil)(mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearerTransport{}}, MaxRetries: -1, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callOK(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("%s: err=%v result=%+v", name, err, res)
	}
	return res
}

func TestCreateSecretToolSendsPaddedValueExactly(t *testing.T) {
	g := &paddingGateway{}
	cs := mcpSession(t, g.serve(t))
	for _, v := range paddedValues {
		callOK(t, cs, toolCreate, map[string]any{"folderId": "f1", "typeId": "t1", "name": "svc",
			"fields": []any{map[string]any{"key": "apiKey", "value": v}}})
		g.mu.Lock()
		got := g.fields
		g.mu.Unlock()
		if len(got) != 1 || got[0].Value != v {
			t.Fatalf("gateway got %+v, want value %q", got, v)
		}
	}
}

func TestGetSecretToolReturnsPaddedValueExactly(t *testing.T) {
	g := &paddingGateway{}
	cs := mcpSession(t, g.serve(t))
	for _, v := range paddedValues {
		g.mu.Lock()
		g.reveal = v
		g.mu.Unlock()
		res := callOK(t, cs, toolGet, map[string]any{"id": "s1", "fieldKey": "apiKey"})

		var structured, text getSecretOut
		b, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(b, &structured); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &text); err != nil {
			t.Fatal(err)
		}
		if structured.Value != v || text.Value != v {
			t.Fatalf("structured %q, text %q, want %q", structured.Value, text.Value, v)
		}
	}
}
