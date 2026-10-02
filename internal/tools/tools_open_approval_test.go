// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const openInBrowser = "open approvalUrl in the user's browser now"

// assertOpensTheApproval checks the text the agent reads, which is the
// structured result as JSON.
func assertOpensTheApproval(t *testing.T, out any, callAgain string) {
	t.Helper()
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var fields struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(b, &fields)
	msg := strings.ToLower(fields.Message)
	if !strings.Contains(msg, strings.ToLower(openInBrowser)) || !strings.Contains(msg, "browser opener") ||
		!strings.Contains(fields.Message, approvalURL) || !strings.Contains(fields.Message, callAgain) {
		t.Fatalf("result text does not tell the agent to open the approval now and call %s again: %s", callAgain, b)
	}
}

func TestGetSecretApprovalTellsTheAgentToOpenTheBrowserNow(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "PENDING"),
	})
	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatal(err)
	}
	assertOpensTheApproval(t, out, toolRedeem)
}

func TestPendingRedeemTellsTheAgentToOpenTheBrowserNow(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{"secretUse(": useBody("secretUse", "PENDING")})
	_, out, err := newTools(gw.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil {
		t.Fatal(err)
	}
	assertOpensTheApproval(t, out, toolRedeem)
}

func TestApprovalToolDescriptionsSayToOpenTheBrowser(t *testing.T) {
	seen := 0
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolGet && tl.Name != toolRedeem {
			continue
		}
		seen++
		if !strings.Contains(tl.Description, "open approvalUrl in the user's browser") {
			t.Errorf("%s description does not say to open the approval in the browser: %q", tl.Name, tl.Description)
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 tools", seen)
	}
}
