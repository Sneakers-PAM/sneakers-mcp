// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

// ChangeSecretType's changeLabel (sneakers-vault#165, via the gateway)
// carries the gateway's own description of the type change through
// unchanged, so a caller's version history reads more than "Changed: host".

func TestChangeSecretTypeDecodesChangeLabel(t *testing.T) {
	var cp capture
	const label = "Type changed: Password -> Password Account (SSH); added host; fields carried over: username, password"
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-unix-ssh"},` +
		`"fieldKeys":["host","username","password"],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"ATTACHED"},` +
		`"changeLabel":"` + label + `"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "type-unix-ssh", nil, nil)
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	if !strings.Contains(cp.query, "changeLabel") {
		t.Fatalf("query must select changeLabel: %q", cp.query)
	}
	if res.ChangeLabel == nil || *res.ChangeLabel != label {
		t.Fatalf("changeLabel = %v, want %q", res.ChangeLabel, label)
	}
}

func TestChangeSecretTypeChangeLabelNilWhenGatewaySendsNone(t *testing.T) {
	var cp capture
	body := `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"},` +
		`"fieldKeys":[],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"NOT_SUPPORTED"}}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).ChangeSecretType(context.Background(), "tok", "s1", "type-password", nil, nil)
	if err != nil {
		t.Fatalf("ChangeSecretType: %v", err)
	}
	if res.ChangeLabel != nil {
		t.Fatalf("changeLabel = %v, want nil", *res.ChangeLabel)
	}
}
