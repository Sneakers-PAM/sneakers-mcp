// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// gatewayReply is the fake machine-GraphQL answer per operation. The generate
// reply always carries a value, so the tests prove the MCP layer (not the
// fake) enforces the returnValue disclosure rule in both result forms.
func gatewayReply(body string) string {
	sum := `{"id":"s1","name":"svc","folderId":"f1","typeId":"t1"}`
	folder := `{"id":"f9","name":"SSH Keys","parentId":"f1","path":"SSH Keys","canAuthor":true}`
	switch {
	case strings.Contains(body, "updateSecretFieldsForPrincipal"):
		return `{"data":{"updateSecretFieldsForPrincipal":{"secret":` + sum + `,"changedFieldKeys":["url"]}}}`
	case strings.Contains(body, "setSecretAutomationForPrincipal"):
		return `{"data":{"setSecretAutomationForPrincipal":` + sum + `}}`
	case strings.Contains(body, "renameSecretForPrincipal"):
		return `{"data":{"renameSecretForPrincipal":` + sum + `}}`
	case strings.Contains(body, "createFolderForPrincipal"):
		return `{"data":{"createFolderForPrincipal":` + folder + `}}`
	case strings.Contains(body, "renameFolderForPrincipal"):
		return `{"data":{"renameFolderForPrincipal":` + folder + `}}`
	case strings.Contains(body, "findSecretsForPrincipal"):
		return `{"data":{"findSecretsForPrincipal":[` + sum + `]}}`
	case strings.Contains(body, "createSecretForPrincipal"):
		return `{"data":{"createSecretForPrincipal":` + sum + `}}`
	case strings.Contains(body, "generateSecretForPrincipal"):
		return `{"data":{"generateSecretForPrincipal":{"secret":` + sum + `,"generatedValue":"GENERATED-VALUE"}}}`
	case strings.Contains(body, "moveSecretForPrincipal"):
		return `{"data":{"moveSecretForPrincipal":` + sum + `}}`
	case strings.Contains(body, "changeSecretTypeForPrincipal"):
		return `{"data":{"changeSecretTypeForPrincipal":{"secret":` + sum + `,"fieldKeys":["password","username"]}}}`
	case strings.Contains(body, "foldersForPrincipal"):
		return `{"data":{"foldersForPrincipal":[{"id":"f1","name":"Infra","parentId":null,"path":"Infra","canAuthor":true}]}}`
	case strings.Contains(body, "redeemSecretUse"):
		return `{"data":{"redeemSecretUse":{"value":"REVEALED-VALUE","use":{"id":"use-1","secretId":"s1","secretName":"svc","fieldKey":"password","argv":[],"state":"REDEEMED","expiresAtUnix":1,"approvalUrl":"https://sneakers.example.org/approvals"}}}}`
	case strings.Contains(body, "secretUse("):
		return `{"data":{"secretUse":{"id":"use-1","secretId":"s1","secretName":"svc","fieldKey":"password","argv":[],"state":"APPROVED","expiresAtUnix":1,"approvalUrl":"https://sneakers.example.org/approvals"}}}`
	case strings.Contains(body, "secretTypes"):
		return `{"data":{"secretTypes":[{"id":"t1","name":"Password","fields":[{"key":"password","label":"Password","kind":"PASSWORD","required":true,"sensitive":true},{"key":"url","label":"URL","kind":"TEXT","required":false,"sensitive":false}]}]}}`
	default:
		return `{"data":{"revealSecretFieldForPrincipal":"REVEALED-VALUE"}}`
	}
}

var structuredCalls = map[string]map[string]any{
	"sneakers_find_secrets":          {"query": "svc"},
	"sneakers_get_secret":            {"id": "s1", "fieldKey": "password"},
	"sneakers_create_secret":         {"folderId": "f1", "typeId": "t1", "name": "svc", "fields": []any{map[string]any{"key": "username", "value": "u"}}},
	"sneakers_generate_secret":       {"folderId": "f1", "typeId": "t1", "name": "svc"},
	"sneakers_move_secret":           {"id": "s1", "destFolderId": "f2"},
	"sneakers_change_secret_type":    {"id": "s1", "newTypeId": "t2"},
	"sneakers_list_folders":          {"query": "inf"},
	"sneakers_list_secret_types":     {},
	"sneakers_redeem_reveal":         {"useId": "use-1"},
	"sneakers_list_connections":      {},
	"sneakers_list_targets":          {"query": "ad"},
	"sneakers_save_target":           {"name": "ad DCs", "hostname": "dc1.ad.example.org", "connectionId": "conn-ldaps"},
	"sneakers_set_secret_target":     {"secretId": "s1", "targetId": "t1"},
	"sneakers_test_secret":           {"secretId": "s1"},
	"sneakers_rename_secret":         {"id": "s1", "name": "svc"},
	"sneakers_create_folder":         {"parentId": "f1", "name": "SSH Keys"},
	"sneakers_rename_folder":         {"id": "f9", "name": "SSH Keys"},
	"sneakers_set_secret_automation": {"id": "s1", "disableRotation": true, "disableHeartbeat": false},
	"sneakers_update_secret":         {"id": "s1", "fields": []any{map[string]any{"key": "url", "value": "https://fw-01.example.org/"}}},
}

func jwtSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	h := newHarness(t)
	cs, err := h.connect(t, h.token(t, "client-a", nil))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return cs
}

// Every tool advertises an object outputSchema.
func TestEveryToolDeclaresAnObjectOutputSchema(t *testing.T) {
	cs := jwtSession(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != len(structuredCalls) {
		t.Fatalf("tools = %d, want %d", len(res.Tools), len(structuredCalls))
	}
	for _, tl := range res.Tools {
		var sch map[string]any
		b, _ := json.Marshal(tl.OutputSchema)
		if err := json.Unmarshal(b, &sch); err != nil || sch["type"] != "object" || sch["properties"] == nil {
			t.Fatalf("%s outputSchema = %s, want an object schema", tl.Name, b)
		}
	}
}

// Every successful call returns structuredContent AND the same object as JSON
// text in content[0] (for text-only clients).
func TestEveryToolReturnsStructuredContentMatchingText(t *testing.T) {
	cs := jwtSession(t)
	for name, args := range structuredCalls {
		t.Run(name, func(t *testing.T) {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
			if err != nil || res.IsError {
				t.Fatalf("CallTool: err=%v result=%+v", err, res)
			}
			if res.StructuredContent == nil {
				t.Fatal("structuredContent missing")
			}
			if len(res.Content) != 1 {
				t.Fatalf("content blocks = %d, want 1", len(res.Content))
			}
			tc, ok := res.Content[0].(*mcp.TextContent)
			if !ok {
				t.Fatalf("content[0] is %T, want text", res.Content[0])
			}
			var fromText, fromStructured any
			if err := json.Unmarshal([]byte(tc.Text), &fromText); err != nil {
				t.Fatalf("text content is not JSON: %v", err)
			}
			b, _ := json.Marshal(res.StructuredContent)
			_ = json.Unmarshal(b, &fromStructured)
			if !reflect.DeepEqual(fromText, fromStructured) {
				t.Fatalf("text %s != structured %s", tc.Text, b)
			}
		})
	}
}

// Secret values obey the same disclosure rule in both forms: get returns the
// revealed value in both; generate returns the generated value in neither
// unless returnValue is true.
func TestSecretValueDisclosureIsIdenticalInTextAndStructured(t *testing.T) {
	cs := jwtSession(t)
	both := func(res *mcp.CallToolResult) (string, string) {
		b, _ := json.Marshal(res.StructuredContent)
		return res.Content[0].(*mcp.TextContent).Text, string(b)
	}
	call := func(name string, args map[string]any) *mcp.CallToolResult {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || res.IsError {
			t.Fatalf("%s: err=%v result=%+v", name, err, res)
		}
		return res
	}

	txt, st := both(call("sneakers_get_secret", structuredCalls["sneakers_get_secret"]))
	if !strings.Contains(txt, "REVEALED-VALUE") || !strings.Contains(st, "REVEALED-VALUE") {
		t.Fatalf("get: text=%s structured=%s", txt, st)
	}
	txt, st = both(call("sneakers_generate_secret", structuredCalls["sneakers_generate_secret"]))
	if strings.Contains(txt, "GENERATED-VALUE") || strings.Contains(st, "GENERATED-VALUE") {
		t.Fatalf("generate without returnValue disclosed the value: text=%s structured=%s", txt, st)
	}
	txt, st = both(call("sneakers_generate_secret", map[string]any{"folderId": "f1", "typeId": "t1", "name": "svc", "returnValue": true}))
	if !strings.Contains(txt, "GENERATED-VALUE") || !strings.Contains(st, "GENERATED-VALUE") {
		t.Fatalf("generate with returnValue: text=%s structured=%s", txt, st)
	}
}

// Wire-level: the raw JSON-RPC answer carries structuredContent and
// outputSchema, independent of how any client library decodes them.
func TestRawWireCarriesStructuredContentAndOutputSchema(t *testing.T) {
	h := newHarness(t)
	tok := h.token(t, "client-a", nil)
	post := func(body string) string {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`); strings.Count(got, `"outputSchema"`) != len(structuredCalls) {
		t.Fatalf("tools/list wire = %s", got)
	}
	got := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sneakers_move_secret","arguments":{"id":"s1","destFolderId":"f2"}}}`)
	if !strings.Contains(got, `"structuredContent"`) || !strings.Contains(got, `"content"`) {
		t.Fatalf("tools/call wire = %s", got)
	}
}
