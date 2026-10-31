// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const summaryOK = `{"data":{"secretForPrincipal":` + signalled + `}}`

const summaryRefused = `{"data":null,"errors":[{"message":"rpc error: code = Unavailable desc = vault down"}]}`

func TestGetSecretThroughAnAllowRevealGrantReturnsTheSummaryReadBeforeTheValue(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"revealSecretFieldForPrincipal": approvalRequired,
		"prepareSecretUse":              useBody("prepareSecretUse", "APPROVED"),
		"redeemSecretUse":               redeemed,
		"secretForPrincipal":            summaryOK,
	})
	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil || out.Value != "hunter2" {
		t.Fatalf("out = %+v err = %v, want the value", out, err)
	}
	if out.Secret == nil || out.Secret.ValueVersion != 4 || out.Secret.ValueChangedAt != "2026-10-01T12:00:00Z" {
		t.Fatalf("summary = %+v, want the change signals with the value", out.Secret)
	}
	if slices.Index(gw.seen, "secretForPrincipal") > slices.Index(gw.seen, "redeemSecretUse") {
		t.Fatalf("order = %v, want the summary before the value", gw.seen)
	}
}

func TestRedeemRevealReturnsTheUsesSummaryReadBeforeTheValue(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{
		"secretUse(":         useBody("secretUse", "APPROVED"),
		"redeemSecretUse":    redeemed,
		"secretForPrincipal": summaryOK,
	})
	var logs bytes.Buffer
	_, out, err := newTools(gw.URL, &logs).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil || out.Value != "hunter2" {
		t.Fatalf("out = %+v err = %v, want the value", out, err)
	}
	if out.Secret == nil || out.Secret.ValueVersion != 4 || out.Secret.ValueChangedAt != "2026-10-01T12:00:00Z" {
		t.Fatalf("summary = %+v, want the change signals with the value", out.Secret)
	}
	if want := []string{"secretUse(", "secretForPrincipal", "redeemSecretUse"}; !slices.Equal(gw.seen, want) {
		t.Fatalf("order = %v, want %v so the version is never newer than the value", gw.seen, want)
	}
	if gw.summaryID != "s1" {
		t.Fatalf("summary read for %q, want the use's secret s1", gw.summaryID)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("log carries the value")
	}
}

func TestRedeemRevealStillRedeemsOnceWhenTheSummaryFails(t *testing.T) {
	for name, body := range map[string]string{"refused": summaryRefused, "malformed": "not json"} {
		t.Run(name, func(t *testing.T) {
			gw := newRouteGateway(t, map[string]string{
				"secretUse(":         useBody("secretUse", "APPROVED"),
				"redeemSecretUse":    redeemed,
				"secretForPrincipal": body,
			})
			_, out, err := newTools(gw.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
			if err != nil || out.Value != "hunter2" || out.Secret != nil {
				t.Fatalf("out = %+v err = %v, want the value without a summary", out, err)
			}
			redeems := 0
			for _, op := range gw.seen {
				if op == "redeemSecretUse" {
					redeems++
				}
			}
			if redeems != 1 {
				t.Fatalf("redeemed %d times in %v, want once: a reveal is one-shot", redeems, gw.seen)
			}
		})
	}
}

// A use is only collectable for 60 seconds, so a summary read that hangs must
// give up well before the client's own timeout would.
func TestRedeemRevealDoesNotWaitOutAHungSummaryRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := string(b)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "secretForPrincipal"):
			<-r.Context().Done()
		case strings.Contains(q, "redeemSecretUse"):
			_, _ = io.WriteString(w, redeemed)
		default:
			_, _ = io.WriteString(w, useBody("secretUse", "APPROVED"))
		}
	}))
	t.Cleanup(srv.Close)

	tools := newTools(srv.URL, nil)
	tools.metaTimeout = 50 * time.Millisecond
	start := time.Now()
	_, out, err := tools.redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil || out.Value != "hunter2" || out.Secret != nil {
		t.Fatalf("out = %+v err = %v, want the value without a summary", out, err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v, want the summary read bounded", d)
	}
}

func TestRedeemRevealReadsNoSummaryUntilTheUseIsApproved(t *testing.T) {
	gw := newRouteGateway(t, map[string]string{"secretUse(": useBody("secretUse", "PENDING"), "secretForPrincipal": summaryOK})
	_, out, err := newTools(gw.URL, nil).redeemReveal(context.Background(), callReq("Bearer snk_u_tok"), redeemRevealIn{UseID: "use-1"})
	if err != nil || !out.Pending || out.Secret != nil {
		t.Fatalf("out = %+v err = %v", out, err)
	}
	if slices.Contains(gw.seen, "secretForPrincipal") {
		t.Fatalf("seen = %v, want no summary read for a pending use", gw.seen)
	}
}
