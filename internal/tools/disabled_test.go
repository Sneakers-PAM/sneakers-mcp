// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

func restrictedSession(t *testing.T, gwURL string, disabled []string) *mcp.ClientSession {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Register(s, gwclient.New(gwURL, nil), zerolog.Nop())
	Restrict(s, disabled, zerolog.Nop())
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestDisabledToolIsNotListed(t *testing.T) {
	cs := restrictedSession(t, "http://unused", []string{"sneakers_rotate_secret"})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	if slices.Contains(names, "sneakers_rotate_secret") {
		t.Fatal("a disabled tool is still offered")
	}
	if !slices.Contains(names, "sneakers_find_secrets") {
		t.Fatal("an enabled tool went missing")
	}
	if len(names) != len(Names())-1 {
		t.Fatalf("listed %d tools, want %d", len(names), len(Names())-1)
	}
}

func TestDisabledToolIsRefusedNamingTheSetting(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	cs := restrictedSession(t, gw.URL, []string{"sneakers_find_secrets"})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "sneakers_find_secrets", Arguments: map[string]any{}})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("a disabled tool was run")
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			msg = tc.Text
		}
	}
	if !strings.Contains(msg, "MCP_DISABLED_TOOLS") {
		t.Fatalf("refusal %q does not name the setting", msg)
	}
	if gw.calls.Load() != 0 {
		t.Fatal("a refused call reached the gateway")
	}
}

func TestEnabledToolStillRuns(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	cs := restrictedSession(t, gw.URL, []string{"sneakers_rotate_secret"})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "sneakers_list_secret_types", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != nil && res.IsError {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && strings.Contains(tc.Text, "MCP_DISABLED_TOOLS") {
				t.Fatalf("an enabled tool was refused as disabled: %s", tc.Text)
			}
		}
	}
}

func TestParseDisabled(t *testing.T) {
	got, err := ParseDisabled(" sneakers_rotate_secret, sneakers_find_secrets ,,")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"sneakers_rotate_secret", "sneakers_find_secrets"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := ParseDisabled(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: got %v, %v", got, err)
	}
	if _, err := ParseDisabled("sneakers_rotate_secret,sneakers_typo"); err == nil || !strings.Contains(err.Error(), "sneakers_typo") {
		t.Fatalf("an unknown name must be refused naming it, got %v", err)
	}
}
