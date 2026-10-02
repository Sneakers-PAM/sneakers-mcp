// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMoveSecretForwardsTokenAndReturnsSummary(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"moveSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f2","typeId":"t"}}}`)

	_, out, err := newTools(gw.URL, nil).moveSecret(context.Background(), callReq("Bearer agent-tok"), moveSecretIn{ID: "s1", DestFolderID: "f2"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Secret.ID != "s1" || out.Secret.FolderID != "f2" {
		t.Fatalf("Secret = %+v", out.Secret)
	}
	if gw.gotAuth() != "Bearer agent-tok" {
		t.Fatalf("gateway saw Authorization %q", gw.gotAuth())
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if vars["id"] != "s1" || vars["destFolderId"] != "f2" {
		t.Fatalf("vars = %#v", vars)
	}
}

func TestChangeSecretTypeForwardsMappingAndFields(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-secure-note"},"fieldKeys":["description","note"]}}}`)

	in := changeSecretTypeIn{
		ID: "s1", NewTypeID: "type-secure-note",
		FieldMapping: []mappingIn{{From: "password", To: "note"}, {From: "username", To: "description"}},
	}
	_, out, err := newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), in)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Secret.TypeID != "type-secure-note" || strings.Join(out.FieldKeys, ",") != "description,note" {
		t.Fatalf("out = %+v", out)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if fm, _ := vars["fieldMapping"].([]any); len(fm) != 2 {
		t.Fatalf("fieldMapping forwarded = %#v", vars["fieldMapping"])
	}
}

// RACI denials (no rights on source/destination, read-only) and the vault's
// refusal to drop a value come back from the gateway as GraphQL errors; both
// must reach the agent as tool errors with no result.
func TestMoveAndChangeTypeDenialsSurfaceAsToolErrors(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = PermissionDenied desc = not permitted to move the secret to that folder"}]}`)
	ts := newTools(gw.URL, nil)
	_, mout, err := ts.moveSecret(context.Background(), callReq("Bearer t"), moveSecretIn{ID: "s1", DestFolderID: "f2"})
	if err == nil || !strings.Contains(err.Error(), "not permitted") || mout.Secret.ID != "" {
		t.Fatalf("move denial: err=%v out=%+v", err, mout)
	}

	gw2 := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = type change would drop the value of field(s) notes"}]}`)
	ts2 := newTools(gw2.URL, nil)
	_, cout, err := ts2.changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "t2"})
	if err == nil || !strings.Contains(err.Error(), "would drop") || cout.Secret.ID != "" || cout.FieldKeys != nil {
		t.Fatalf("change-type refusal: err=%v out=%+v", err, cout)
	}
}

// A disabled service account is rejected by the gateway with HTTP 401; the
// tool reports a credentials error and returns nothing.
func TestMoveAndChangeTypeDisabledAccountIsCredentialsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	ts := newTools(srv.URL, nil)
	if _, _, err := ts.moveSecret(context.Background(), callReq("Bearer t"), moveSecretIn{ID: "s1", DestFolderID: "f2"}); err == nil || !strings.Contains(err.Error(), "rejected the caller's credentials") {
		t.Fatalf("move: err = %v", err)
	}
	if _, _, err := ts.changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "t2"}); err == nil || !strings.Contains(err.Error(), "rejected the caller's credentials") {
		t.Fatalf("change type: err = %v", err)
	}
}

func TestMoveAndChangeTypeUnauthenticatedNeverReachGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	noInfo := callReq("Bearer t")
	noInfo.Extra.TokenInfo = nil
	if _, _, err := ts.moveSecret(context.Background(), noInfo, moveSecretIn{ID: "s1", DestFolderID: "f2"}); err == nil {
		t.Fatal("move without verified bearer must fail")
	}
	if _, _, err := ts.changeSecretType(context.Background(), noInfo, changeSecretTypeIn{ID: "s1", NewTypeID: "t2"}); err == nil {
		t.Fatal("change type without verified bearer must fail")
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times", gw.calls.Load())
	}
}

func TestMoveAndChangeTypeInputLimits(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	ctx := context.Background()
	long := func(n int) string { return strings.Repeat("x", n) }
	many := make([]mappingIn, maxFields+1)
	for i := range many {
		many[i] = mappingIn{From: "k" + long(i), To: "v"}
	}
	move := func(in moveSecretIn) func() error {
		return func() error { _, _, err := ts.moveSecret(ctx, callReq("Bearer t"), in); return err }
	}
	retype := func(in changeSecretTypeIn) func() error {
		return func() error { _, _, err := ts.changeSecretType(ctx, callReq("Bearer t"), in); return err }
	}
	checks := map[string]func() error{
		"move: id missing":           move(moveSecretIn{DestFolderID: "f"}),
		"move: dest missing":         move(moveSecretIn{ID: "s"}),
		"move: id too long":          move(moveSecretIn{ID: long(maxIDLen + 1), DestFolderID: "f"}),
		"move: dest too long":        move(moveSecretIn{ID: "s", DestFolderID: long(maxIDLen + 1)}),
		"retype: id missing":         retype(changeSecretTypeIn{NewTypeID: "t"}),
		"retype: type missing":       retype(changeSecretTypeIn{ID: "s"}),
		"retype: type too long":      retype(changeSecretTypeIn{ID: "s", NewTypeID: long(maxIDLen + 1)}),
		"retype: too many mappings":  retype(changeSecretTypeIn{ID: "s", NewTypeID: "t", FieldMapping: many}),
		"retype: mapping from empty": retype(changeSecretTypeIn{ID: "s", NewTypeID: "t", FieldMapping: []mappingIn{{To: "a"}}}),
		"retype: mapping to empty":   retype(changeSecretTypeIn{ID: "s", NewTypeID: "t", FieldMapping: []mappingIn{{From: "a"}}}),
		"retype: mapping key too long": retype(changeSecretTypeIn{ID: "s", NewTypeID: "t",
			FieldMapping: []mappingIn{{From: long(maxFieldKeyLen + 1), To: "a"}}}),
		"retype: duplicate mapping": retype(changeSecretTypeIn{ID: "s", NewTypeID: "t",
			FieldMapping: []mappingIn{{From: "a", To: "b"}, {From: "a", To: "c"}}}),
		"retype: field value too long": retype(changeSecretTypeIn{ID: "s", NewTypeID: "t",
			Fields: []fieldIn{{Key: "k", Value: long(maxFieldValueLen + 1)}}}),
		"retype: duplicate field": retype(changeSecretTypeIn{ID: "s", NewTypeID: "t",
			Fields: []fieldIn{{Key: "k", Value: "a"}, {Key: "k", Value: "b"}}}),
	}
	for name, fn := range checks {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times for invalid input", gw.calls.Load())
	}
}

func TestChangeTypeNeverEchoesOrLogsValues(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t2"},"fieldKeys":["url"]}}}`)
	var buf bytes.Buffer
	ts := newTools(gw.URL, &buf)

	secret := "S3CRET-" + strings.Repeat("z", maxFieldValueLen)
	_, _, err := ts.changeSecretType(context.Background(), callReq("Bearer TOKEN-MARKER"),
		changeSecretTypeIn{ID: "s1", NewTypeID: "t2", Fields: []fieldIn{{Key: "url", Value: secret}}})
	if err == nil || strings.Contains(err.Error(), "S3CRET") {
		t.Fatalf("err = %v; must fail without echoing the value", err)
	}
	if _, _, err := ts.changeSecretType(context.Background(), callReq("Bearer TOKEN-MARKER"),
		changeSecretTypeIn{ID: "s1", NewTypeID: "t2", Fields: []fieldIn{{Key: "url", Value: "FIELD-MARKER"}}}); err != nil {
		t.Fatal(err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "sneakers_change_secret_type") {
		t.Fatalf("expected a log line for the tool, got: %s", logs)
	}
	for _, leak := range []string{"TOKEN-MARKER", "FIELD-MARKER", "S3CRET"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log output leaks %s: %s", leak, logs)
		}
	}
}
