// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	updateFindReply  = `{"data":{"findSecretsForPrincipal":[{"id":"s0","name":"other","folderId":"f","typeId":"t0"},{"id":"s1","name":"palo-fw-01","folderId":"f","typeId":"t-login"}]}}`
	updateTypesReply = `{"data":{"secretTypes":[{"id":"t0","name":"Other","fields":[{"key":"endpoint","label":"Endpoint","kind":"TEXT","required":false,"sensitive":false}]},` +
		`{"id":"t-login","name":"Login","fields":[` +
		`{"key":"url","label":"URL","kind":"TEXT","required":false,"sensitive":false},` +
		`{"key":"notes","label":"Notes","kind":"MULTILINE","required":false,"sensitive":false},` +
		`{"key":"password","label":"Password","kind":"PASSWORD","required":true,"sensitive":true}]}]}}`
	updateOKReply = `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"palo-fw-01","folderId":"f","typeId":"t-login"},"changedFieldKeys":["url","notes"]}}}`
)

// routedGW answers each machine GraphQL operation by name and records the
// variables of the update mutation.
type routedGW struct {
	*httptest.Server
	mu         sync.Mutex
	updates    int
	updateVars map[string]any
}

func routedGateway(t *testing.T, updateReply string) *routedGW {
	t.Helper()
	g := &routedGW{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "updateSecretFieldsForPrincipal"):
			g.mu.Lock()
			g.updates++
			g.updateVars = req.Variables
			g.mu.Unlock()
			_, _ = io.WriteString(w, updateReply)
		case strings.Contains(req.Query, "findSecretsForPrincipal"):
			_, _ = io.WriteString(w, updateFindReply)
		case strings.Contains(req.Query, "secretTypes"):
			_, _ = io.WriteString(w, updateTypesReply)
		default:
			http.Error(w, "unexpected operation", http.StatusBadRequest)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *routedGW) updateCalls() (int, map[string]any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.updates, g.updateVars
}

func TestUpdateSecretForwardsExactValuesAndReturnsChangedKeys(t *testing.T) {
	gw := routedGateway(t, updateOKReply)

	_, out, err := newTools(gw.URL, nil).updateSecret(context.Background(), callReq("Bearer agent-tok"), updateSecretIn{
		ID:     "s1",
		Fields: []fieldIn{{Key: "url", Value: "https://fw-01.example.org:4443/"}, {Key: "notes", Value: "  line one\nline two  "}},
	})
	if err != nil {
		t.Fatalf("updateSecret: %v", err)
	}
	if out.Secret.ID != "s1" || out.Secret.TypeID != "t-login" || strings.Join(out.ChangedFieldKeys, ",") != "url,notes" {
		t.Fatalf("out = %+v", out)
	}
	n, vars := gw.updateCalls()
	if n != 1 || vars["id"] != "s1" {
		t.Fatalf("update calls = %d, vars = %#v", n, vars)
	}
	got, _ := json.Marshal(vars["fields"])
	want := `[{"key":"url","value":"https://fw-01.example.org:4443/"},{"key":"notes","value":"  line one\nline two  "}]`
	if string(got) != want {
		t.Fatalf("fields = %s, want %s", got, want)
	}
}

func TestUpdateSecretRefusesSensitiveKeyWithSneakersPutHint(t *testing.T) {
	gw := routedGateway(t, updateOKReply)

	_, out, err := newTools(gw.URL, nil).updateSecret(context.Background(), callReq("Bearer t"), updateSecretIn{
		ID:     "s1",
		Fields: []fieldIn{{Key: "url", Value: "https://fw-01.example.org/"}, {Key: "password", Value: "VALUE-MARKER"}},
	})
	if err == nil {
		t.Fatal("want a refusal for a sensitive key")
	}
	msg := err.Error()
	for _, want := range []string{"password", "sensitive", "sneakers-put -id s1 -field password=@file"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "VALUE-MARKER") {
		t.Fatalf("error echoes the value: %q", msg)
	}
	if n, _ := gw.updateCalls(); n != 0 || out.Secret.ID != "" {
		t.Fatalf("update calls = %d, out = %+v", n, out)
	}
}

func TestUpdateSecretRefusesUndeclaredKey(t *testing.T) {
	gw := routedGateway(t, updateOKReply)

	// endpoint is declared by another type, not by this secret's type.
	_, _, err := newTools(gw.URL, nil).updateSecret(context.Background(), callReq("Bearer t"), updateSecretIn{
		ID: "s1", Fields: []fieldIn{{Key: "endpoint", Value: "192.0.2.1"}},
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint") || !strings.Contains(err.Error(), "not declared") ||
		!strings.Contains(err.Error(), "sneakers-put") {
		t.Fatalf("err = %v", err)
	}
	if n, _ := gw.updateCalls(); n != 0 {
		t.Fatalf("update calls = %d, want 0", n)
	}
}

func TestUpdateSecretRefusesASecretTheTokenCannotSee(t *testing.T) {
	gw := routedGateway(t, updateOKReply)

	_, _, err := newTools(gw.URL, nil).updateSecret(context.Background(), callReq("Bearer t"), updateSecretIn{
		ID: "s-missing", Fields: []fieldIn{{Key: "url", Value: "u"}},
	})
	if err == nil || !strings.Contains(err.Error(), "s-missing") {
		t.Fatalf("err = %v", err)
	}
	if n, _ := gw.updateCalls(); n != 0 {
		t.Fatalf("update calls = %d, want 0", n)
	}
}

func TestUpdateSecretValidatesInputBeforeCallingGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	many := make([]fieldIn, 21)
	for i := range many {
		many[i] = fieldIn{Key: strings.Repeat("k", i+1), Value: "v"}
	}
	cases := map[string]updateSecretIn{
		"id missing":      {Fields: []fieldIn{{Key: "url", Value: "u"}}},
		"id too long":     {ID: strings.Repeat("x", maxIDLen+1), Fields: []fieldIn{{Key: "url", Value: "u"}}},
		"no fields":       {ID: "s1"},
		"too many fields": {ID: "s1", Fields: many},
		"key missing":     {ID: "s1", Fields: []fieldIn{{Value: "u"}}},
		"key too long":    {ID: "s1", Fields: []fieldIn{{Key: strings.Repeat("k", maxFieldKeyLen+1), Value: "u"}}},
		"value too long":  {ID: "s1", Fields: []fieldIn{{Key: "notes", Value: strings.Repeat("v", maxFieldValueLen+1)}}},
		"duplicate key":   {ID: "s1", Fields: []fieldIn{{Key: "url", Value: "a"}, {Key: "url", Value: "b"}}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ts.updateSecret(context.Background(), callReq("Bearer t"), in); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times for invalid input", gw.calls.Load())
	}
}

func TestUpdateSecretGatewayDenialSurfacesAsToolError(t *testing.T) {
	gw := routedGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = PermissionDenied desc = not permitted to author this secret"}]}`)

	_, out, err := newTools(gw.URL, nil).updateSecret(context.Background(), callReq("Bearer t"), updateSecretIn{
		ID: "s1", Fields: []fieldIn{{Key: "url", Value: "u"}},
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted to author this secret") || out.Secret.ID != "" {
		t.Fatalf("err = %v, out = %+v", err, out)
	}
	if n, _ := gw.updateCalls(); n != 1 {
		t.Fatalf("update calls = %d, want 1", n)
	}
}

func TestUpdateSecretLogsNoValuesOrTokens(t *testing.T) {
	var buf bytes.Buffer
	ts := newTools(routedGateway(t, updateOKReply).URL, &buf)

	if _, _, err := ts.updateSecret(context.Background(), callReq("Bearer TOKEN-MARKER"), updateSecretIn{
		ID: "s1", Fields: []fieldIn{{Key: "url", Value: "URL-VALUE-MARKER"}},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, _ = ts.updateSecret(context.Background(), callReq("Bearer TOKEN-MARKER"), updateSecretIn{
		ID: "s1", Fields: []fieldIn{{Key: "password", Value: "SECRET-VALUE-MARKER"}},
	})
	logs := buf.String()
	if strings.Count(logs, "sneakers_update_secret") != 2 {
		t.Fatalf("expected two log lines for the tool, got: %s", logs)
	}
	for _, leak := range []string{"TOKEN-MARKER", "URL-VALUE-MARKER", "SECRET-VALUE-MARKER"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log output leaks %s: %s", leak, logs)
		}
	}
}

func TestUpdateSecretDescriptionScopesToNonSensitiveFields(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolUpdate {
			continue
		}
		for _, want := range []string{"non-sensitive", "sneakers-put", "audited"} {
			if !strings.Contains(tl.Description, want) {
				t.Fatalf("description lacks %q: %q", want, tl.Description)
			}
		}
		a := tl.Annotations
		if a == nil || a.ReadOnlyHint {
			t.Fatalf("annotations = %+v", a)
		}
		return
	}
	t.Fatalf("%s is not registered", toolUpdate)
}

func TestListSecretTypesShowsWhichFieldsAreSensitive(t *testing.T) {
	gw := routedGateway(t, updateOKReply)

	_, out, err := newTools(gw.URL, nil).listSecretTypes(context.Background(), callReq("Bearer t"), listSecretTypesIn{})
	if err != nil || len(out.Types) != 2 {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	got := map[string]bool{}
	for _, f := range out.Types[1].Fields {
		got[f.Key] = f.Sensitive
	}
	if got["url"] || got["notes"] || !got["password"] {
		t.Fatalf("sensitive flags = %v", got)
	}
}
