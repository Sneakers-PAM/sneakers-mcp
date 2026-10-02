// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretput

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const typesReply = `{"data":{"secretTypes":[{"id":"type-password","name":"Password","fields":[
  {"key":"username","label":"Username","kind":"TEXT","required":false},
  {"key":"password","label":"Password","kind":"PASSWORD","required":true},
  {"key":"note","label":"Note","kind":"MULTILINE","required":false},
  {"key":"token","label":"Token","kind":"SENSITIVE","required":false},
  {"key":"enabled","label":"Enabled","kind":"BOOLEAN","required":false},
  {"key":"env","label":"Env","kind":"SELECT","required":false}]}]}}`

// fakeGateway answers by operation and records every call's variables.
type fakeGateway struct {
	*httptest.Server
	mu      sync.Mutex
	ops     []string
	vars    map[string]map[string]any
	replies map[string]string
}

func newFake(t *testing.T, replies map[string]string) *fakeGateway {
	t.Helper()
	f := &fakeGateway{vars: map[string]map[string]any{}, replies: replies}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		for op, body := range f.replies {
			if strings.Contains(req.Query, op) {
				f.ops = append(f.ops, op)
				f.vars[op] = req.Variables
				_, _ = io.WriteString(w, body)
				return
			}
		}
		http.Error(w, "unexpected operation", http.StatusBadRequest)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGateway) called(op string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.vars[op]
	return ok
}

func (f *fakeGateway) fields(op string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	fs, _ := f.vars[op]["fields"].([]any)
	for _, e := range fs {
		m := e.(map[string]any)
		out[m["key"].(string)] = m["value"].(string)
	}
	return out
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateReadsFileAndStdinTrimsOneNewlineAndOptsOut(t *testing.T) {
	gw := newFake(t, map[string]string{
		"secretTypes":              typesReply,
		"createSecretForPrincipal": `{"data":{"createSecretForPrincipal":{"id":"s1","name":"recovery-admin","folderId":"f1","typeId":"type-password","rotationOptOut":true}}}`,
	})
	pw := writeFile(t, "FILE-VALUE\n\n")
	res, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "recovery-admin", DisableRotation: true,
		Fields: []FieldSpec{
			{Key: "password", Source: SourceFile, Path: pw},
			{Key: "token", Source: SourceStdin},
			{Key: "username", Source: SourceLiteral, Literal: "Administrator"},
		},
		Stdin: strings.NewReader("STDIN-VALUE\r\n"),
	})
	if err != nil || res.ID != "s1" || res.Name != "recovery-admin" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	got := gw.fields("createSecretForPrincipal")
	if got["password"] != "FILE-VALUE\n" || got["token"] != "STDIN-VALUE" || got["username"] != "Administrator" {
		t.Fatalf("fields sent = %q", got)
	}
	gw.mu.Lock()
	v := gw.vars["createSecretForPrincipal"]
	gw.mu.Unlock()
	if v["folderId"] != "f1" || v["typeId"] != "type-password" || v["name"] != "recovery-admin" || v["disableRotation"] != true {
		t.Fatalf("vars = %#v", v)
	}
}

func TestLiteralsAreRefusedForSensitiveOrUndeclaredFields(t *testing.T) {
	gw := newFake(t, map[string]string{"secretTypes": typesReply, "createSecretForPrincipal": `{"data":{}}`})
	for _, key := range []string{"password", "token", "note", "notDeclared"} {
		_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
			Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "n",
			Fields: []FieldSpec{{Key: key, Source: SourceLiteral, Literal: "LITERAL-MARKER"}},
		})
		if err == nil || !strings.Contains(err.Error(), "@file") || !strings.Contains(err.Error(), key+"=-") {
			t.Fatalf("%s: err = %v, want a refusal pointing at @file or -", key, err)
		}
		if strings.Contains(err.Error(), "LITERAL-MARKER") {
			t.Fatalf("%s: error echoes the literal: %v", key, err)
		}
	}
	if gw.called("createSecretForPrincipal") {
		t.Fatal("a refused literal still reached the create")
	}
}

func TestLiteralsAreAllowedForPlainFields(t *testing.T) {
	gw := newFake(t, map[string]string{
		"secretTypes":              typesReply,
		"createSecretForPrincipal": `{"data":{"createSecretForPrincipal":{"id":"s1","name":"n","folderId":"f1","typeId":"type-password"}}}`,
	})
	_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "n",
		Fields: []FieldSpec{
			{Key: "username", Source: SourceLiteral, Literal: "u"},
			{Key: "enabled", Source: SourceLiteral, Literal: "true"},
			{Key: "env", Source: SourceLiteral, Literal: "prod"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnknownTypeIsRefusedWhenALiteralNeedsChecking(t *testing.T) {
	gw := newFake(t, map[string]string{"secretTypes": typesReply, "createSecretForPrincipal": `{"data":{}}`})
	_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", FolderID: "f1", TypeID: "type-nope", Name: "n",
		Fields: []FieldSpec{{Key: "username", Source: SourceLiteral, Literal: "u"}},
	})
	if err == nil || !strings.Contains(err.Error(), "type-nope") || gw.called("createSecretForPrincipal") {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdateSendsFieldsAndReturnsChangedKeys(t *testing.T) {
	gw := newFake(t, map[string]string{
		"updateSecretFieldsForPrincipal": `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f1","typeId":"type-password"},"changedFieldKeys":["password"]}}}`,
	})
	res, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", SecretID: "s1",
		Fields: []FieldSpec{{Key: "password", Source: SourceStdin}},
		Stdin:  strings.NewReader("NEW-VALUE\n"),
	})
	if err != nil || res.ID != "s1" || res.Name != "svc" || strings.Join(res.Changed, ",") != "password" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := gw.fields("updateSecretFieldsForPrincipal"); got["password"] != "NEW-VALUE" {
		t.Fatalf("fields sent = %q", got)
	}
}

func TestUpdateChecksLiteralsAgainstTheSecretsType(t *testing.T) {
	gw := newFake(t, map[string]string{
		"secretTypes":                    typesReply,
		"findSecretsForPrincipal":        `{"data":{"findSecretsForPrincipal":[{"id":"s0","name":"other","folderId":"f1","typeId":"type-x"},{"id":"s1","name":"svc","folderId":"f1","typeId":"type-password"}]}}`,
		"updateSecretFieldsForPrincipal": `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f1","typeId":"type-password"},"changedFieldKeys":["username"]}}}`,
	})
	put := func(key string) error {
		_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
			Token: "snk_u_x", SecretID: "s1", Fields: []FieldSpec{{Key: key, Source: SourceLiteral, Literal: "v"}},
		})
		return err
	}
	if err := put("password"); err == nil || !strings.Contains(err.Error(), "@file") {
		t.Fatalf("sensitive literal on update: err = %v", err)
	}
	if gw.called("updateSecretFieldsForPrincipal") {
		t.Fatal("a refused literal still reached the update")
	}
	if err := put("username"); err != nil {
		t.Fatalf("plain literal on update: %v", err)
	}
}

func TestUpdateRefusesLiteralsWhenTheSecretIsNotVisible(t *testing.T) {
	gw := newFake(t, map[string]string{
		"secretTypes":                    typesReply,
		"findSecretsForPrincipal":        `{"data":{"findSecretsForPrincipal":[]}}`,
		"updateSecretFieldsForPrincipal": `{"data":{}}`,
	})
	_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", SecretID: "s1", Fields: []FieldSpec{{Key: "username", Source: SourceLiteral, Literal: "v"}},
	})
	if err == nil || gw.called("updateSecretFieldsForPrincipal") {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyOrOversizedValuesAreRefusedWithoutEchoing(t *testing.T) {
	gw := newFake(t, map[string]string{"createSecretForPrincipal": `{"data":{}}`})
	big := writeFile(t, "BIG-MARKER"+strings.Repeat("z", maxFieldValueLen))
	for name, spec := range map[string]FieldSpec{
		"empty file":   {Key: "password", Source: SourceFile, Path: writeFile(t, "\n")},
		"too big":      {Key: "password", Source: SourceFile, Path: big},
		"missing file": {Key: "password", Source: SourceFile, Path: filepath.Join(t.TempDir(), "nope")},
	} {
		_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
			Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "n", Fields: []FieldSpec{spec},
		})
		if err == nil || strings.Contains(err.Error(), "BIG-MARKER") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if gw.called("createSecretForPrincipal") {
		t.Fatal("a bad value reached the create")
	}
}

func TestGatewayErrorsHaveValuesRedacted(t *testing.T) {
	gw := newFake(t, map[string]string{
		"createSecretForPrincipal": `{"data":null,"errors":[{"message":"value FILE-SECRET fails policy; STDIN-SECRET too"}]}`,
	})
	_, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "n",
		Fields: []FieldSpec{
			{Key: "password", Source: SourceFile, Path: writeFile(t, "FILE-SECRET")},
			{Key: "token", Source: SourceStdin},
		},
		Stdin: strings.NewReader("STDIN-SECRET"),
	})
	if err == nil || strings.Contains(err.Error(), "FILE-SECRET") || strings.Contains(err.Error(), "STDIN-SECRET") || !strings.Contains(err.Error(), "fails policy") {
		t.Fatalf("err = %v", err)
	}
}

func TestRedactRemovesAValueThatContainsAnotherWhole(t *testing.T) {
	err := redact(errorString("bad: abc-LONGER-abc"), []string{"abc", "abc-LONGER-abc"})
	if strings.Contains(err.Error(), "LONGER") || strings.Contains(err.Error(), "abc") {
		t.Fatalf("err = %v", err)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
