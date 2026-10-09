// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"testing"
)

const placed = `{"id":"s1","name":"lab vpn","folderId":"f-mine","typeId":"type-password",` +
	`"placement":{"folderId":"f-mine","requestedFolderId":"f-shared","rule":"PERSONAL_DEFAULT","reason":"the secret's name matches your username"}}`

func TestCreateSecretToolForwardsKeepFolderAndReportsThePlacement(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":`+placed+`}}`)
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"),
		createSecretIn{FolderID: "f-shared", TypeID: "type-password", Name: "lab vpn", KeepFolder: true})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || vars["keepFolder"] != true {
		t.Fatalf("err=%v vars=%#v", err, vars)
	}
	p := out.Placement
	if p == nil || p.FolderID != "f-mine" || p.RequestedFolderID != "f-shared" || p.Rule != "PERSONAL_DEFAULT" || p.Reason == "" || out.Secret.FolderID != "f-mine" {
		t.Fatalf("out=%+v placement=%+v", out, p)
	}
}

func TestGenerateSecretToolForwardsKeepFolderAndReportsThePlacement(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"generateSecretForPrincipal":{"secret":`+placed+`,"generatedValue":null}}}`)
	_, out, err := newTools(gw.URL, nil).generateSecret(context.Background(), callReq("Bearer t"),
		generateSecretIn{FolderID: "f-shared", TypeID: "type-password", Name: "lab vpn"})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || vars["keepFolder"] != nil {
		t.Fatalf("err=%v vars=%#v", err, vars)
	}
	if out.Placement == nil || out.Placement.Rule != "PERSONAL_DEFAULT" {
		t.Fatalf("out=%+v", out)
	}
}

func TestPlacementIsLeftOutWhenTheGatewaySendsNone(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f","typeId":"t"}}}`)
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"),
		createSecretIn{FolderID: "f", TypeID: "t", Name: "svc"})
	if err != nil || out.Placement != nil {
		t.Fatalf("err=%v placement=%+v", err, out.Placement)
	}
}
