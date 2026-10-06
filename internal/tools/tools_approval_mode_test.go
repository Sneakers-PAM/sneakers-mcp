// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strings"
	"testing"
)

func confirmUseBody(op string) string {
	return `{"data":{"` + op + `":{"id":"use-1","secretId":"s1","secretName":"domain-admin","fieldKey":"password","argv":[],"state":"PENDING","expiresAtUnix":1790000600,"approvalUrl":"` + approvalURL + `","confirm":true}}}`
}

func TestGetSecretAsksTheUserToConfirmOnceWhenNobodyElseDecides(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              confirmUseBody("prepareSecretUse"),
	})
	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.ConfirmRequired || !out.ApprovalRequired {
		t.Fatalf("out = %+v, want a confirmation", out)
	}
	if !strings.Contains(out.Message, "confirm") || !strings.Contains(out.Message, "once") || strings.Contains(out.Message, "owner or approver") {
		t.Fatalf("message = %q, want the user to confirm the task once", out.Message)
	}
	assertOpensTheApproval(t, out, toolRedeem)
}

func TestGetSecretSaysAnotherPersonDecidesWhenOneCan(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "PENDING"),
	})
	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ConfirmRequired || !strings.Contains(out.Message, "owner or approver") || strings.Contains(out.Message, "The owner must approve") {
		t.Fatalf("out = %+v, want another owner or approver to decide", out)
	}
}

func TestPendingRedeemOfAConfirmationAsksTheUserToConfirm(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{"secretUse(": confirmUseBody("secretUse")})
	_, out, err := newTools(gw.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Message, "confirm") {
		t.Fatalf("message = %q", out.Message)
	}
}
