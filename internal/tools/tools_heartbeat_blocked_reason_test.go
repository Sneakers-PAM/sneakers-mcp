// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"testing"
)

// createSecret's result carries heartbeatBlockedReason through unchanged
// (sneakers-vault#162), so a create result can say "heartbeat available:
// switch it on" or name what's missing, without a second round trip.
func TestCreateSecretReportsHeartbeatBlockedReason(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":{"id":"s2","name":"svc","folderId":"f","typeId":"type-ssh-key",`+
		`"heartbeatBlockedReason":"no pinned host key"}}}`)

	in := createSecretIn{FolderID: "f", TypeID: "type-ssh-key", Name: "svc"}
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"), in)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Secret.HeartbeatBlockedReason != "no pinned host key" {
		t.Fatalf("heartbeatBlockedReason = %q, want \"no pinned host key\"", out.Secret.HeartbeatBlockedReason)
	}
}

func TestCreateSecretHeartbeatBlockedReasonEmptyWhenReady(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":{"id":"s2","name":"svc","folderId":"f","typeId":"type-ssh-key",`+
		`"heartbeatEnabled":true}}}`)

	in := createSecretIn{FolderID: "f", TypeID: "type-ssh-key", Name: "svc"}
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"), in)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Secret.HeartbeatBlockedReason != "" {
		t.Fatalf("heartbeatBlockedReason = %q, want empty", out.Secret.HeartbeatBlockedReason)
	}
}
