// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretput

import (
	"context"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const placedReply = `{"data":{"createSecretForPrincipal":{"id":"s1","name":"lab vpn","folderId":"f-mine","typeId":"type-password",` +
	`"placement":{"folderId":"f-mine","requestedFolderId":"f1","rule":"PERSONAL_DEFAULT","reason":"the secret's username field matches your username"}}}}`

func TestCreatePassesKeepFolderAndReturnsThePlacement(t *testing.T) {
	gw := newFake(t, map[string]string{"secretTypes": typesReply, "createSecretForPrincipal": placedReply})
	res, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "tok", FolderID: "f1", TypeID: "type-password", Name: "lab vpn", KeepFolder: true,
		Fields: []FieldSpec{{Key: "username", Source: SourceLiteral, Literal: "ada"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gw.mu.Lock()
	v := gw.vars["createSecretForPrincipal"]["keepFolder"]
	gw.mu.Unlock()
	if v != true {
		t.Fatalf("keepFolder = %#v, want true", v)
	}
	if p := res.Placement; p == nil || p.FolderID != "f-mine" || p.Rule != "PERSONAL_DEFAULT" {
		t.Fatalf("placement = %+v", res.Placement)
	}
}
