// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

const useJSON = `{"id":"use-1","secretId":"s1","secretName":"router-admin","fieldKey":"password","argv":["ssh","admin@router-01"],"state":"PENDING","expiresAtUnix":1790000600,"approvalUrl":"https://sneakers.example.org/approvals"}`

func TestPrepareSecretUseSendsTheBoundCommand(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"prepareSecretUse":`+useJSON+`}}`, 200)

	u, err := New(srv.URL, nil).PrepareSecretUse(context.Background(), "snk_u_x", "s1", "password", []string{"ssh", "admin@router-01"}, "laptop")
	if err != nil {
		t.Fatalf("PrepareSecretUse: %v", err)
	}
	if u.ID != "use-1" || u.State != "PENDING" || u.ApprovalURL == "" || len(u.Argv) != 2 {
		t.Fatalf("got %+v", u)
	}
	argv, _ := cp.vars["argv"].([]any)
	if cp.auth != "Bearer snk_u_x" || !strings.Contains(cp.query, "prepareSecretUse") ||
		cp.vars["secretId"] != "s1" || cp.vars["fieldKey"] != "password" || cp.vars["clientLabel"] != "laptop" || len(argv) != 2 {
		t.Fatalf("auth=%q query=%q vars=%#v", cp.auth, cp.query, cp.vars)
	}
}

func TestSecretUsePollsById(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"secretUse":`+useJSON+`}}`, 200)

	u, err := New(srv.URL, nil).SecretUse(context.Background(), "snk_u_x", "use-1")
	if err != nil || u.State != "PENDING" || cp.vars["id"] != "use-1" {
		t.Fatalf("u=%+v err=%v vars=%#v", u, err, cp.vars)
	}
}

func TestRedeemSecretUseReturnsValueAndBoundUse(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"redeemSecretUse":{"value":"s3cret","use":`+useJSON+`}}}`, 200)

	value, u, err := New(srv.URL, nil).RedeemSecretUse(context.Background(), "snk_u_x", "use-1")
	if err != nil || value != "s3cret" || u.ID != "use-1" || strings.Join(u.Argv, " ") != "ssh admin@router-01" {
		t.Fatalf("value=%q u=%+v err=%v", value, u, err)
	}
}

func TestPrepareRevealAsksForTheValueWithNoCommand(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"prepareSecretUse":`+useJSON+`}}`, 200)

	u, err := New(srv.URL, nil).PrepareReveal(context.Background(), "snk_u_x", "s1", "password", "Sneakers MCP")
	if err != nil || u.ID != "use-1" {
		t.Fatalf("u=%+v err=%v", u, err)
	}
	if cp.vars["reveal"] != true || cp.vars["argv"] != nil || cp.vars["secretId"] != "s1" || cp.vars["clientLabel"] != "Sneakers MCP" {
		t.Fatalf("vars = %#v", cp.vars)
	}
	if !strings.Contains(cp.query, "reveal:$reveal") {
		t.Fatalf("query = %q", cp.query)
	}
}
