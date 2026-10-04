// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const signalled = `{"id":"s1","name":"svc","folderId":"f","typeId":"type-windows-domain","valueVersion":4,` +
	`"valueChangedAt":"2026-10-01T12:00:00Z","rotationEnabled":true,"rotatesOnCheckin":true,"heartbeatEnabled":false,"lastRotationResult":"OK"}`

func TestFindSecretsForwardsChangedSinceAndShowsTheSignals(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"findSecretsForPrincipal":[`+signalled+`]}}`)
	_, out, err := newTools(gw.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{ChangedSince: "2026-10-01T00:00:00Z"})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || vars["changedSince"] != "2026-10-01T00:00:00Z" || len(out.Secrets) != 1 {
		t.Fatalf("err=%v vars=%#v out=%+v", err, vars, out)
	}
	s := out.Secrets[0]
	if s.ValueVersion != 4 || s.ValueChangedAt != "2026-10-01T12:00:00Z" || !s.RotationEnabled || !s.RotatesOnCheckin || s.LastRotationResult != "OK" {
		t.Fatalf("summary = %+v", s)
	}
}

func TestFindSecretsRefusesABadChangedSinceBeforeCallingTheGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	if _, _, err := newTools(gw.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{ChangedSince: "yesterday"}); err == nil || !strings.Contains(err.Error(), "RFC3339") {
		t.Fatalf("err = %v", err)
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times", gw.calls.Load())
	}
}

// orderGateway answers the summary read and the reveal, recording the order.
type orderGateway struct {
	mu      sync.Mutex
	order   []string
	summary string
}

func (g *orderGateway) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(b, &req)
		g.mu.Lock()
		defer g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.Query, "revealSecretFieldForPrincipal"):
			g.order = append(g.order, "reveal")
			_, _ = io.WriteString(w, `{"data":{"revealSecretFieldForPrincipal":"hunter2"}}`)
		case strings.Contains(req.Query, "secretForPrincipal"):
			g.order = append(g.order, "summary")
			_, _ = io.WriteString(w, g.summary)
		default:
			http.Error(w, "unexpected query", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestGetSecretReadsTheSummaryBeforeTheValue(t *testing.T) {
	g := &orderGateway{summary: `{"data":{"secretForPrincipal":` + signalled + `}}`}
	_, out, err := newTools(g.serve(t), nil).getSecret(context.Background(), callReq("Bearer t"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil || out.Value != "hunter2" || out.Secret == nil || out.Secret.ValueVersion != 4 || !out.Secret.RotatesOnCheckin {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if strings.Join(g.order, ",") != "summary,reveal" {
		t.Fatalf("order = %v, want the summary first so the version is never newer than the value", g.order)
	}
}

func TestGetSecretStillReturnsTheValueWhenTheSummaryFails(t *testing.T) {
	g := &orderGateway{summary: `{"data":null,"errors":[{"message":"rpc error: code = Unimplemented desc = unknown method"}]}`}
	_, out, err := newTools(g.serve(t), nil).getSecret(context.Background(), callReq("Bearer t"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil || out.Value != "hunter2" || out.Secret != nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}
