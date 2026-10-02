// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"encoding/json"
	"testing"
)

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

const paddingSummary = `{"id":"s1","name":"svc","folderId":"f","typeId":"t"}`

func sentFieldValue(t *testing.T, cp *capture) string {
	t.Helper()
	fs, _ := cp.vars["fields"].([]any)
	if len(fs) != 1 {
		t.Fatalf("fields = %#v, want one field", cp.vars["fields"])
	}
	v, _ := fs[0].(map[string]any)["value"].(string)
	return v
}

func TestCreateSecretSendsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		var cp capture
		srv := newFakeGateway(t, &cp, `{"data":{"createSecretForPrincipal":`+paddingSummary+`}}`, 200)
		if _, err := New(srv.URL, nil).CreateSecret(context.Background(), "tok", "f", "t", "svc", []Field{{Key: "apiKey", Value: v}}, ""); err != nil {
			t.Fatalf("CreateSecret: %v", err)
		}
		if got := sentFieldValue(t, &cp); got != v {
			t.Fatalf("sent %q, want %q", got, v)
		}
	}
}

func TestGenerateSecretSendsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		var cp capture
		srv := newFakeGateway(t, &cp, `{"data":{"generateSecretForPrincipal":{"secret":`+paddingSummary+`}}}`, 200)
		if _, _, err := New(srv.URL, nil).GenerateSecret(context.Background(), "tok", "f", "t", "svc", []Field{{Key: "apiKey", Value: v}}, "", "", false); err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		if got := sentFieldValue(t, &cp); got != v {
			t.Fatalf("sent %q, want %q", got, v)
		}
	}
}

func TestUpdateSecretFieldsSendsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		var cp capture
		srv := newFakeGateway(t, &cp, `{"data":{"updateSecretFieldsForPrincipal":{"secret":`+paddingSummary+`,"changedFieldKeys":["apiKey"]}}}`, 200)
		if _, _, err := New(srv.URL, nil).UpdateSecretFields(context.Background(), "tok", "s1", []Field{{Key: "apiKey", Value: v}}); err != nil {
			t.Fatalf("UpdateSecretFields: %v", err)
		}
		if got := sentFieldValue(t, &cp); got != v {
			t.Fatalf("sent %q, want %q", got, v)
		}
	}
}

func TestRevealFieldReturnsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		enc, _ := json.Marshal(v)
		var cp capture
		srv := newFakeGateway(t, &cp, `{"data":{"revealSecretFieldForPrincipal":`+string(enc)+`}}`, 200)
		got, err := New(srv.URL, nil).RevealField(context.Background(), "tok", "s1", "apiKey")
		if err != nil {
			t.Fatalf("RevealField: %v", err)
		}
		if got != v {
			t.Fatalf("revealed %q, want %q", got, v)
		}
	}
}

func TestRedeemSecretUseReturnsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		enc, _ := json.Marshal(v)
		var cp capture
		body := `{"data":{"redeemSecretUse":{"value":` + string(enc) + `,"use":{"id":"use-1","secretId":"s1","secretName":"svc","fieldKey":"apiKey","argv":[],"state":"REDEEMED","expiresAtUnix":1,"approvalUrl":"https://sneakers.example.org/approvals"}}}}`
		srv := newFakeGateway(t, &cp, body, 200)
		got, _, err := New(srv.URL, nil).RedeemSecretUse(context.Background(), "tok", "use-1")
		if err != nil {
			t.Fatalf("RedeemSecretUse: %v", err)
		}
		if got != v {
			t.Fatalf("redeemed %q, want %q", got, v)
		}
	}
}
