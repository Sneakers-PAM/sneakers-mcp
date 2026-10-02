// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestUpdateSecretFieldsSendsFieldsAndReturnsChangedKeys(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t"},"changedFieldKeys":["password"]}}}`, 200)

	s, keys, err := New(srv.URL, nil).UpdateSecretFields(context.Background(), "tok", "s1", []Field{{Key: "password", Value: "p"}})
	if err != nil || s.ID != "s1" || strings.Join(keys, ",") != "password" {
		t.Fatalf("s=%+v keys=%v err=%v", s, keys, err)
	}
	if cp.auth != "Bearer tok" || !strings.Contains(cp.query, "updateSecretFieldsForPrincipal") || !strings.Contains(cp.query, summaryFields) {
		t.Fatalf("auth=%q query=%q", cp.auth, cp.query)
	}
	fs, _ := cp.vars["fields"].([]any)
	if cp.vars["id"] != "s1" || len(fs) != 1 || fs[0].(map[string]any)["key"] != "password" {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestUpdateSecretFieldsNeverReturnsNilKeys(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t"},"changedFieldKeys":null}}}`, 200)
	_, keys, err := New(srv.URL, nil).UpdateSecretFields(context.Background(), "tok", "s1", nil)
	if err != nil || keys == nil {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if fs, ok := cp.vars["fields"].([]any); !ok || len(fs) != 0 {
		t.Fatalf("fields = %#v, want an empty JSON array", cp.vars["fields"])
	}
}

func TestUpdateSecretFieldsDenialIsAGraphQLError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":null,"errors":[{"message":"not permitted to change this secret"}]}`, 200)
	var ge *GraphQLError
	if _, _, err := New(srv.URL, nil).UpdateSecretFields(context.Background(), "tok", "s1", nil); !errors.As(err, &ge) {
		t.Fatalf("err = %v", err)
	}
}
