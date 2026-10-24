// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// outputSchemas resolves every tool's advertised outputSchema, by tool name.
func outputSchemas(t *testing.T, cs *mcp.ClientSession) map[string]*jsonschema.Resolved {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*jsonschema.Resolved{}
	for _, tl := range res.Tools {
		b, err := json.Marshal(tl.OutputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("%s outputSchema: %v", tl.Name, err)
		}
		r, err := s.Resolve(nil)
		if err != nil {
			t.Fatalf("%s outputSchema: %v", tl.Name, err)
		}
		out[tl.Name] = r
	}
	return out
}

// checkStructured calls a tool and validates its structuredContent against
// the tool's own outputSchema, the check an MCP client makes on a result.
func checkStructured(t *testing.T, cs *mcp.ClientSession, schemas map[string]*jsonschema.Resolved, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("%s: err=%v result=%+v", name, err, res)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal(b, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schemas[name].Validate(instance); err != nil {
		t.Fatalf("%s structuredContent %s does not match its outputSchema: %v", name, b, err)
	}
	m, _ := instance.(map[string]any)
	return m
}

// Every tool's result matches the outputSchema it advertises.
func TestEveryToolResultMatchesItsOutputSchema(t *testing.T) {
	cs := jwtSession(t)
	schemas := outputSchemas(t, cs)
	for name, args := range structuredCalls {
		t.Run(name, func(t *testing.T) {
			checkStructured(t, cs, schemas, name, args)
		})
	}
}

// withGatewayReplies puts replies ahead of the shared fake answers for one test.
func withGatewayReplies(t *testing.T, replies ...struct{ match, body string }) {
	t.Helper()
	saved := gatewayReplies
	gatewayReplies = append(replies, saved...)
	t.Cleanup(func() { gatewayReplies = saved })
}

// sneakers_get_secret matches its outputSchema in each shape it returns: a
// value with the secret's summary, an empty field, and approval required.
func TestGetSecretResultShapesMatchTheOutputSchema(t *testing.T) {
	summary := struct{ match, body string }{"secretForPrincipal", `{"data":{"secretForPrincipal":{"id":"s1","name":"svc","folderId":"f1","typeId":"t1","targetIds":["t1"],"valueVersion":3,"rotationEnabled":true,"lastRotationResult":"OK"}}}`}
	use := `{"id":"use-1","secretId":"s1","secretName":"svc","fieldKey":"password","argv":[],"state":"PENDING","expiresAtUnix":1790000600,"approvalUrl":"https://sneakers.example.org/approvals"}`
	for _, tc := range []struct {
		name    string
		replies []struct{ match, body string }
		field   string
		want    string
	}{
		{"value with summary", []struct{ match, body string }{summary}, "password", "secret"},
		{"non-sensitive field", []struct{ match, body string }{summary}, "notes", "secret"},
		{"empty field", []struct{ match, body string }{summary, {"revealSecretFieldForPrincipal", `{"data":{"revealSecretFieldForPrincipal":""}}`}}, "notes", "value"},
		{"approval required", []struct{ match, body string }{
			{"revealSecretFieldForPrincipal", `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = approval_required: this secret needs the owner's approval for each token reveal; prepare a reveal use"}]}`},
			{"prepareSecretUse", `{"data":{"prepareSecretUse":` + use + `}}`},
			{"secretUseRun", `{"data":{"secretUseRun":[` + use + `]}}`},
		}, "password", "approvalRequired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGatewayReplies(t, tc.replies...)
			cs := jwtSession(t)
			got := checkStructured(t, cs, outputSchemas(t, cs), "sneakers_get_secret", map[string]any{"id": "s1", "fieldKey": tc.field})
			if _, ok := got[tc.want]; !ok {
				t.Fatalf("result %v has no %q, so it isn't the %s shape", got, tc.want, tc.name)
			}
		})
	}
}
