// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// runGateway keeps the uses it prepared, so secretUseRun answers with what
// was really raised in each run.
type runGateway struct {
	*httptest.Server
	mu       sync.Mutex
	uses     []map[string]any
	purposes []any
}

func newRunGateway(t *testing.T) *runGateway {
	t.Helper()
	g := &runGateway{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(b, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "revealSecretFieldForPrincipal"):
			_, _ = io.WriteString(w, approvalRequired)
		case strings.Contains(req.Query, "prepareSecretUse"):
			runID, _ := req.Variables["runId"].(string)
			u := map[string]any{
				"id": fmt.Sprintf("use-%d", len(g.uses)+1), "secretId": req.Variables["secretId"],
				"secretName": "name-" + fmt.Sprint(req.Variables["secretId"]), "fieldKey": req.Variables["fieldKey"],
				"argv": []string{}, "state": "PENDING", "expiresAtUnix": 1790000600, "reveal": true,
				"runId": runID, "approvalUrl": approvalURL + "/run/" + runID,
			}
			g.uses = append(g.uses, u)
			g.purposes = append(g.purposes, req.Variables["purpose"])
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"prepareSecretUse": u}})
		case strings.Contains(req.Query, "secretUseRun("):
			out := []map[string]any{}
			for _, u := range g.uses {
				if u["runId"] == req.Variables["runId"] {
					out = append(out, u)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"secretUseRun": out}})
		default:
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func TestThreeUsesInOneRunShareOneLinkListingAllThree(t *testing.T) {
	gw := newRunGateway(t)
	ts := newTools(gw.URL, nil)
	ctx := context.Background()

	_, first, err := ts.getSecret(ctx, callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password", Task: "rotate the lab switches"})
	if err != nil || !first.ApprovalRequired || first.RunID == "" {
		t.Fatalf("first: out=%+v err=%v", first, err)
	}
	var last getSecretOut
	for _, id := range []string{"s2", "s3"} {
		_, last, err = ts.getSecret(ctx, callReq("Bearer snk_u_tok"), getSecretIn{ID: id, FieldKey: "password", RunID: first.RunID, Task: "rotate the lab switches"})
		if err != nil || last.RunID != first.RunID {
			t.Fatalf("%s: out=%+v err=%v", id, last, err)
		}
	}
	if want := approvalURL + "/run/" + first.RunID; first.ApprovalURL != want || last.ApprovalURL != want {
		t.Fatalf("links %q / %q, want one link %q", first.ApprovalURL, last.ApprovalURL, want)
	}
	assertPendingInOrder(t, last.Pending, 3)
	if last.UseID != "use-3" || !strings.Contains(last.Message, first.RunID) || !strings.Contains(last.Message, "3") {
		t.Fatalf("useId=%q message=%q", last.UseID, last.Message)
	}
}

func assertPendingInOrder(t *testing.T, pending []pendingUse, n int) {
	t.Helper()
	if len(pending) != n {
		t.Fatalf("pending = %+v, want %d uses", pending, n)
	}
	for i, p := range pending {
		if p.UseID != fmt.Sprintf("use-%d", i+1) || p.SecretName != fmt.Sprintf("name-s%d", i+1) || p.FieldKey != "password" || !p.Reveal || p.ExpiresAtUnix == 0 {
			t.Errorf("pending[%d] = %+v", i, p)
		}
	}
}

func TestAGetWithoutARunIDStartsANewRun(t *testing.T) {
	gw := newRunGateway(t)
	ts := newTools(gw.URL, nil)
	_, a, err := ts.getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := ts.getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s2", FieldKey: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if a.RunID == "" || a.RunID == b.RunID || len(a.Pending) != 1 || len(b.Pending) != 1 || a.ApprovalURL == b.ApprovalURL {
		t.Fatalf("a=%+v b=%+v, want two separate runs of one", a, b)
	}
}

func TestTheTaskIsSentAsACleanPurpose(t *testing.T) {
	gw := newRunGateway(t)
	_, _, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"),
		getSecretIn{ID: "s1", FieldKey: "password", Task: "  check\tthe\nbackup\x1b[31m job \xfe "})
	if err != nil {
		t.Fatal(err)
	}
	if len(gw.purposes) != 1 || gw.purposes[0] != "check the backup[31m job" {
		t.Fatalf("purposes = %#v", gw.purposes)
	}
}

func TestAMalformedRunIDIsAnInputError(t *testing.T) {
	gw := newRunGateway(t)
	for _, bad := range []string{"run id", "run/1", strings.Repeat("a", 65)} {
		_, _, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password", RunID: bad})
		if err == nil || !strings.Contains(err.Error(), "runId") {
			t.Errorf("%q: err = %v, want an input error naming runId", bad, err)
		}
	}
	if len(gw.uses) != 0 {
		t.Fatalf("a use was prepared for a bad run id")
	}
}

func TestASinglePendingUseStillWorksWhenTheRunCantBeListed(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "PENDING"),
	})
	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil || !out.ApprovalRequired || out.UseID != "use-1" || out.RunID == "" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if len(out.Pending) != 1 || out.Pending[0].UseID != "use-1" || out.Pending[0].SecretName != "router-admin" {
		t.Fatalf("pending = %+v, want the one use", out.Pending)
	}
}

func TestGetSecretDescriptionTellsTheAgentToCarryTheRunID(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolGet {
			continue
		}
		for _, want := range []string{"runId", "task", "pending", "new task without a runId", "once"} {
			if !strings.Contains(tl.Description, want) {
				t.Errorf("description lacks %q: %q", want, tl.Description)
			}
		}
		return
	}
	t.Fatal(toolGet + " not registered")
}
