// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestListFoldersDecodesAndSendsNullForEmptyFilters(t *testing.T) {
	var cp capture
	body := `{"data":{"foldersForPrincipal":[{"id":"f1","name":"Infra","parentId":null,"path":"Infra","canAuthor":true}]}}`
	srv := newFakeGateway(t, &cp, body, 200)

	out, err := New(srv.URL, nil).ListFolders(context.Background(), "t", "inf", "")
	if err != nil {
		t.Fatalf("ListFolders: %v", err)
	}
	if len(out) != 1 || out[0].ID != "f1" || out[0].Path != "Infra" || !out[0].CanAuthor || out[0].ParentID != nil {
		t.Fatalf("decoded = %+v", out)
	}
	if !strings.Contains(cp.query, "foldersForPrincipal") || cp.vars["query"] != "inf" {
		t.Fatalf("query/vars wrong: %q %v", cp.query, cp.vars)
	}
	if v, ok := cp.vars["parentId"]; !ok || v != nil {
		t.Fatalf("parentId = %v (present=%v), want explicit null", v, ok)
	}
}

func TestListSecretTypesDecodesFields(t *testing.T) {
	var cp capture
	body := `{"data":{"secretTypes":[{"id":"type-password","name":"Password","fields":[{"key":"password","label":"Password","kind":"PASSWORD","required":true}]}]}}`
	srv := newFakeGateway(t, &cp, body, 200)

	out, err := New(srv.URL, nil).ListSecretTypes(context.Background(), "t")
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	if len(out) != 1 || out[0].ID != "type-password" || len(out[0].Fields) != 1 ||
		out[0].Fields[0].Kind != "PASSWORD" || !out[0].Fields[0].Required {
		t.Fatalf("decoded = %+v", out)
	}
	if cp.auth != "Bearer t" {
		t.Fatalf("Authorization = %q", cp.auth)
	}
}

func TestListEmptyAreEmptySlicesNotNil(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"foldersForPrincipal":null,"secretTypes":null}}`, 200)
	c := New(srv.URL, nil)
	if f, err := c.ListFolders(context.Background(), "t", "", ""); err != nil || f == nil {
		t.Fatalf("ListFolders = %v, %v; want empty non-nil", f, err)
	}
	if ty, err := c.ListSecretTypes(context.Background(), "t"); err != nil || ty == nil {
		t.Fatalf("ListSecretTypes = %v, %v; want empty non-nil", ty, err)
	}
}

func TestListSecretTypesAsksForAndDecodesSensitive(t *testing.T) {
	var cp capture
	body := `{"data":{"secretTypes":[{"id":"t1","name":"Login","fields":[` +
		`{"key":"url","label":"URL","kind":"TEXT","required":false,"sensitive":false},` +
		`{"key":"password","label":"Password","kind":"PASSWORD","required":true,"sensitive":true}]}]}}`
	srv := newFakeGateway(t, &cp, body, 200)

	out, err := New(srv.URL, nil).ListSecretTypes(context.Background(), "t")
	if err != nil {
		t.Fatalf("ListSecretTypes: %v", err)
	}
	if !strings.Contains(cp.query, "sensitive") {
		t.Fatalf("query does not select sensitive: %q", cp.query)
	}
	if len(out) != 1 || len(out[0].Fields) != 2 || out[0].Fields[0].Sensitive || !out[0].Fields[1].Sensitive {
		t.Fatalf("decoded = %+v", out)
	}
}
