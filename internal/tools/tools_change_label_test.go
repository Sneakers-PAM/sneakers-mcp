// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"testing"
)

// changeSecretType's result carries the gateway's changeLabel through
// unchanged (sneakers-vault#165), instead of leaving the caller to guess
// what a type change did from fieldKeys alone.
func TestChangeSecretTypeReportsChangeLabel(t *testing.T) {
	const label = "Type changed: Password -> Password Account (SSH); added host; fields carried over: username, password"
	gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-unix-ssh"},`+
		`"fieldKeys":["host","username","password"],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"ATTACHED"},`+
		`"changeLabel":"`+label+`"}}}`)
	_, out, err := newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "type-unix-ssh"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.ChangeLabel != label {
		t.Fatalf("changeLabel = %q, want %q", out.ChangeLabel, label)
	}
}

func TestChangeSecretTypeChangeLabelEmptyForAPlainUpdate(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"},`+
		`"fieldKeys":[],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"NOT_SUPPORTED"}}}}`)
	_, out, err := newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "type-password"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.ChangeLabel != "" {
		t.Fatalf("changeLabel = %q, want empty", out.ChangeLabel)
	}
}
