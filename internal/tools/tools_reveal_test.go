// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const approvalURL = "https://sneakers.example.org/approvals"

// routeGateway answers each machine operation by name, recording the order.
type routeGateway struct {
	*httptest.Server
	mu     sync.Mutex
	bodies map[string]string
	seen   []string
}

func newRouteGateway(t *testing.T, bodies map[string]string) *routeGateway {
	t.Helper()
	g := &routeGateway{bodies: bodies}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(b, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		for _, op := range []string{"revealSecretFieldForPrincipal", "prepareSecretUse", "redeemSecretUse", "secretUse("} {
			if strings.Contains(req.Query, op) {
				g.seen = append(g.seen, op)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, g.bodies[op])
				return
			}
		}
		http.Error(w, "unexpected query", http.StatusBadRequest)
	}))
	t.Cleanup(g.Close)
	return g
}

func useBody(op, state string) string {
	return `{"data":{"` + op + `":{"id":"use-1","secretId":"s1","secretName":"router-admin","fieldKey":"password","argv":[],"state":"` + state + `","expiresAtUnix":1790000600,"approvalUrl":"` + approvalURL + `"}}}`
}

const approvalRequired = `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = approval_required: this secret needs the owner's approval for each token reveal; prepare a reveal use"}]}`

const redeemed = `{"data":{"redeemSecretUse":{"value":"hunter2","use":{"id":"use-1","secretId":"s1","secretName":"router-admin","fieldKey":"password","argv":[],"state":"REDEEMED","expiresAtUnix":1790000600,"approvalUrl":"` + approvalURL + `"}}}}`

func TestGetSecretOfAnApprovalSecretReturnsTheApprovalLinkNotAValue(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "PENDING"),
	})
	var logs bytes.Buffer
	_, out, err := newTools(gw.URL, &logs).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatalf("an approval-required secret is not an error: %v", err)
	}
	if out.Value != "" || !out.ApprovalRequired || out.ApprovalURL != approvalURL || out.UseID != "use-1" || out.ExpiresAtUnix == 0 {
		t.Fatalf("out = %+v, want the approval link and use id without a value", out)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("log carries a value")
	}
}

func TestGetSecretCoveredByAnAllowRevealGrantReturnsTheValue(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "APPROVED"),
		"redeemSecretUse":               redeemed,
	})
	var logs bytes.Buffer
	_, out, err := newTools(gw.URL, &logs).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil || out.Value != "hunter2" || out.ApprovalRequired {
		t.Fatalf("out = %+v err = %v, want the value", out, err)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("log carries the value")
	}
}

func TestRedeemRevealWaitsForApprovalThenReleasesOnce(t *testing.T) {
	pending := newRouteGateway(t, map[string]string{"secretUse(": useBody("secretUse", "PENDING")})
	_, out, err := newTools(pending.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil || !out.Pending || out.ApprovalURL != approvalURL || out.Value != "" {
		t.Fatalf("pending: out = %+v err = %v", out, err)
	}

	approved := newRouteGateway(t, map[string]string{"secretUse(": useBody("secretUse", "APPROVED"), "redeemSecretUse": redeemed})
	var logs bytes.Buffer
	_, out, err = newTools(approved.URL, &logs).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil || out.Value != "hunter2" || out.Pending {
		t.Fatalf("approved: out = %+v err = %v", out, err)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("log carries the value")
	}

	for _, st := range []string{"DENIED", "EXPIRED", "REDEEMED"} {
		g := newRouteGateway(t, map[string]string{"secretUse(": useBody("secretUse", st)})
		_, out, err := newTools(g.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
		if err == nil || out.Value != "" || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(st)) {
			t.Errorf("%s: out = %+v err = %v, want an error naming the state", st, out, err)
		}
	}
}

func TestRedeemRevealNeedsAUseID(t *testing.T) {
	g := newRouteGateway(t, map[string]string{})
	if _, _, err := newTools(g.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{}); err == nil {
		t.Fatal("want an input error")
	}
}
