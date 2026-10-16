// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

// heartbeatBlockedReason (sneakers-vault#162, via the gateway) is part of
// summaryFields, the one field selection every SecretSummary-returning
// operation shares, so GetSecret (as a stand-in for the rest) decodes it.

func TestGetSecretDecodesHeartbeatBlockedReason(t *testing.T) {
	var cp capture
	body := `{"data":{"secretForPrincipal":{"id":"s1","name":"svc","folderId":"f","typeId":"type-ssh-key",` +
		`"heartbeatBlockedReason":"no pinned host key"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).GetSecret(context.Background(), "tok", "s1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if !strings.Contains(cp.query, "heartbeatBlockedReason") {
		t.Fatalf("query must select heartbeatBlockedReason: %q", cp.query)
	}
	if res.HeartbeatBlockedReason == nil || *res.HeartbeatBlockedReason != "no pinned host key" {
		t.Fatalf("heartbeatBlockedReason = %v, want \"no pinned host key\"", res.HeartbeatBlockedReason)
	}
}

func TestGetSecretHeartbeatBlockedReasonNilWhenGatewaySendsNone(t *testing.T) {
	var cp capture
	body := `{"data":{"secretForPrincipal":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	res, err := New(srv.URL, nil).GetSecret(context.Background(), "tok", "s1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if res.HeartbeatBlockedReason != nil {
		t.Fatalf("heartbeatBlockedReason = %v, want nil", *res.HeartbeatBlockedReason)
	}
}
