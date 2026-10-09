// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

const placedSummary = `{"id":"s1","name":"lab vpn","folderId":"f-mine","typeId":"t",` +
	`"placement":{"folderId":"f-mine","requestedFolderId":"f-shared","rule":"PERSONAL_DEFAULT","reason":"the secret's username field matches your username"}}`

func TestCreateAndGenerateSendKeepFolderAndDecodeThePlacement(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"createSecretForPrincipal":`+placedSummary+`}}`, 200)
	c := New(srv.URL, nil)

	s, err := c.CreateSecret(context.Background(), "tok", "f-shared", "t", "lab vpn", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := cp.vars["keepFolder"]; !ok || v != nil {
		t.Fatalf("keepFolder = %#v (present=%v), want explicit null by default", v, ok)
	}
	p := s.Placement
	if p == nil || p.FolderID != "f-mine" || p.RequestedFolderID != "f-shared" || p.Rule != "PERSONAL_DEFAULT" || !strings.Contains(p.Reason, "username field") {
		t.Fatalf("placement = %+v", p)
	}
	if _, err := c.CreateSecret(context.Background(), "tok", "f-shared", "t", "lab vpn", nil, "", Automation{KeepFolder: true}); err != nil {
		t.Fatal(err)
	}
	if cp.vars["keepFolder"] != true {
		t.Fatalf("keepFolder = %#v, want true", cp.vars["keepFolder"])
	}

	srv2 := newFakeGateway(t, &cp, `{"data":{"generateSecretForPrincipal":{"secret":`+placedSummary+`,"generatedValue":null}}}`, 200)
	g, _, err := New(srv2.URL, nil).GenerateSecret(context.Background(), "tok", "f-shared", "t", "lab vpn", nil, "", "", false, Automation{KeepFolder: true})
	if err != nil || g.Placement == nil || g.Placement.Rule != "PERSONAL_DEFAULT" {
		t.Fatalf("g=%+v err=%v", g, err)
	}
	if cp.vars["keepFolder"] != true {
		t.Fatalf("generate keepFolder = %#v, want true", cp.vars["keepFolder"])
	}
}

func TestOnlyCreateAndGenerateAskForThePlacement(t *testing.T) {
	for name, q := range map[string]string{"create": createQuery, "generate": generateQuery} {
		if !strings.Contains(q, "placement{folderId requestedFolderId rule reason}") || !strings.Contains(q, "keepFolder:$keepFolder") {
			t.Errorf("%s query lacks keepFolder or the placement: %s", name, q)
		}
	}
	if strings.Contains(findQuery, "placement") {
		t.Error("find asks for a placement the gateway only sets on a create")
	}
}
