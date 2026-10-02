// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestChangeSecretTypeDecodesAutomation(t *testing.T) {
	var cp capture
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-active-directory","rotationOptOut":true},` +
		`"fieldKeys":["domain","password","username"],"automation":{"rotation":"OFF","heartbeat":"NO_TARGET","target":"NONE"}}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "type-active-directory", nil, nil)
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	if !strings.Contains(cp.query, "automation{rotation heartbeat target}") {
		t.Fatalf("query must select automation: %q", cp.query)
	}
	if res.Automation != (TypeChangeAutomation{Rotation: "OFF", Heartbeat: "NO_TARGET", Target: "NONE"}) {
		t.Fatalf("automation = %+v", res.Automation)
	}
	if res.Secret.TypeID != "type-active-directory" || strings.Join(res.FieldKeys, ",") != "domain,password,username" {
		t.Fatalf("got %+v", res)
	}
}

func TestChangeSecretTypeDecodesMovedToNotesKeys(t *testing.T) {
	var cp capture
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"},` +
		`"fieldKeys":["notes"],"movedToNotesKeys":["domain"],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"NOT_SUPPORTED"}}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "type-password", nil, nil)
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	if !strings.Contains(cp.query, "movedToNotesKeys") {
		t.Fatalf("query must select movedToNotesKeys: %q", cp.query)
	}
	if strings.Join(res.MovedToNotesKeys, ",") != "domain" {
		t.Fatalf("movedToNotesKeys = %v", res.MovedToNotesKeys)
	}
}
