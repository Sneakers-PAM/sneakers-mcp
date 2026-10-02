// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestListFoldersMapsFoldersAndForwardsFilters(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"foldersForPrincipal":[`+
		`{"id":"f1","name":"Infra","parentId":null,"path":"Infra","canAuthor":false},`+
		`{"id":"f2","name":"SA","parentId":"f1","path":"Infra/SA","canAuthor":true}]}}`)

	_, out, err := newTools(gw.URL, nil).listFolders(context.Background(), callReq("Bearer t"), listFoldersIn{Query: "s", ParentID: "f1"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if gw.gotAuth() != "Bearer t" {
		t.Fatalf("Authorization = %q", gw.gotAuth())
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if vars["query"] != "s" || vars["parentId"] != "f1" {
		t.Fatalf("filters not forwarded: %v", vars)
	}
	if len(out.Folders) != 2 || out.Folders[0].ParentID != "" || out.Folders[1].ParentID != "f1" ||
		out.Folders[1].Path != "Infra/SA" || !out.Folders[1].CanAuthor {
		t.Fatalf("Folders = %+v", out.Folders)
	}
}

func TestListSecretTypesMapsFields(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"secretTypes":[{"id":"type-secure-note","name":"Secure Note","fields":[`+
		`{"key":"description","label":"Description","kind":"TEXT","required":false},`+
		`{"key":"note","label":"Note","kind":"MULTILINE","required":true}]}]}}`)

	_, out, err := newTools(gw.URL, nil).listSecretTypes(context.Background(), callReq("Bearer t"), listSecretTypesIn{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if len(out.Types) != 1 || out.Types[0].ID != "type-secure-note" || len(out.Types[0].Fields) != 2 ||
		out.Types[0].Fields[1].Key != "note" || !out.Types[0].Fields[1].Required {
		t.Fatalf("Types = %+v", out.Types)
	}
}

func TestListToolsEmptyAreEmptyListsNotNull(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"foldersForPrincipal":[],"secretTypes":[]}}`)
	ts := newTools(gw.URL, nil)
	_, f, err := ts.listFolders(context.Background(), callReq("Bearer t"), listFoldersIn{})
	if err != nil {
		t.Fatal(err)
	}
	_, ty, err := ts.listSecretTypes(context.Background(), callReq("Bearer t"), listSecretTypesIn{})
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := json.Marshal(f)
	tb, _ := json.Marshal(ty)
	if string(fb) != `{"folders":[]}` || string(tb) != `{"types":[]}` {
		t.Fatalf("marshalled = %s %s", fb, tb)
	}
}

func TestListFoldersInputLimitsRejectBeforeCallingGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"foldersForPrincipal":[]}}`)
	ts := newTools(gw.URL, nil)
	for _, in := range []listFoldersIn{{Query: strings.Repeat("q", maxQueryLen+1)}, {ParentID: strings.Repeat("p", maxIDLen+1)}} {
		if _, _, err := ts.listFolders(context.Background(), callReq("Bearer t"), in); err == nil {
			t.Fatalf("oversized input %+v accepted", in)
		}
	}
	if n := gw.calls.Load(); n != 0 {
		t.Fatalf("gateway called %d times for invalid input", n)
	}
}

func TestListToolsRequireAuthentication(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"secretTypes":[]}}`)
	if _, _, err := newTools(gw.URL, nil).listSecretTypes(context.Background(), callReq(""), listSecretTypesIn{}); err == nil {
		t.Fatal("unauthenticated call accepted")
	}
	if n := gw.calls.Load(); n != 0 {
		t.Fatalf("gateway called %d times without a bearer", n)
	}
}
