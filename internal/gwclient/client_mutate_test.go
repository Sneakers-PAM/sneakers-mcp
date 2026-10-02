// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestMoveSecretSendsArgsAndDecodesSummary(t *testing.T) {
	var cp capture
	body := `{"data":{"moveSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f2","typeId":"t"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	s, err := New(srv.URL, nil).MoveSecret(context.Background(), "tok", "s1", "f2")
	if err != nil {
		t.Fatalf("MoveSecret: %v", err)
	}
	if s.ID != "s1" || s.FolderID != "f2" {
		t.Fatalf("got %+v", s)
	}
	if cp.auth != "Bearer tok" || !strings.Contains(cp.query, "moveSecretForPrincipal") {
		t.Fatalf("auth=%q query=%q", cp.auth, cp.query)
	}
	if cp.vars["id"] != "s1" || cp.vars["destFolderId"] != "f2" {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestChangeSecretTypeSendsMappingAndFields(t *testing.T) {
	var cp capture
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t2"},"fieldKeys":["note","description"]}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "t2",
		[]Mapping{{From: "password", To: "note"}}, []Field{{Key: "description", Value: "d"}})
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	s, keys := res.Secret, res.FieldKeys
	if s.TypeID != "t2" || strings.Join(keys, ",") != "note,description" {
		t.Fatalf("got %+v / %v", s, keys)
	}
	if cp.vars["id"] != "s1" || cp.vars["newTypeId"] != "t2" {
		t.Fatalf("vars = %#v", cp.vars)
	}
	fm, _ := cp.vars["fieldMapping"].([]any)
	if len(fm) != 1 || fm[0].(map[string]any)["from"] != "password" || fm[0].(map[string]any)["to"] != "note" {
		t.Fatalf("fieldMapping = %#v", cp.vars["fieldMapping"])
	}
	if fs, _ := cp.vars["fields"].([]any); len(fs) != 1 {
		t.Fatalf("fields = %#v", cp.vars["fields"])
	}
}

func TestChangeSecretTypeOmitsEmptyOptionalLists(t *testing.T) {
	var cp capture
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t2"},"fieldKeys":[]}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "t2", nil, nil)
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	keys := res.FieldKeys
	if keys == nil {
		t.Fatal("keys must be non-nil")
	}
	for _, k := range []string{"fieldMapping", "fields"} {
		if v, ok := cp.vars[k]; !ok || v != nil {
			t.Fatalf("%s = %v (present=%v), want explicit null", k, v, ok)
		}
	}
}
