// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestPrepareSendsTheRunIDAndACleanPurpose(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"prepareSecretUse":`+useJSON+`}}`, 200)
	c := New(srv.URL, nil)
	run := Run{ID: "run_abc", Purpose: " deploy\tthe\r\napp\x07 to staging \xff\x00now "}

	if _, err := c.PrepareReveal(context.Background(), "snk_u_x", "s1", "password", "Sneakers MCP", run); err != nil {
		t.Fatal(err)
	}
	if cp.vars["runId"] != "run_abc" || cp.vars["purpose"] != "deploy the app to staging now" ||
		!strings.Contains(cp.query, "runId:$runId") || !strings.Contains(cp.query, "purpose:$purpose") {
		t.Fatalf("reveal: query=%q vars=%#v", cp.query, cp.vars)
	}

	if _, err := c.PrepareSecretUse(context.Background(), "snk_u_x", "s1", "password", []string{"ssh", "h"}, "laptop", run); err != nil {
		t.Fatal(err)
	}
	if cp.vars["runId"] != "run_abc" || cp.vars["purpose"] != "deploy the app to staging now" ||
		!strings.Contains(cp.query, "runId:$runId") || !strings.Contains(cp.query, "purpose:$purpose") {
		t.Fatalf("use: query=%q vars=%#v", cp.query, cp.vars)
	}
}

func TestPrepareWithoutARunSendsNulls(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"prepareSecretUse":`+useJSON+`}}`, 200)
	if _, err := New(srv.URL, nil).PrepareReveal(context.Background(), "snk_u_x", "s1", "password", "Sneakers MCP"); err != nil {
		t.Fatal(err)
	}
	if cp.vars["runId"] != nil || cp.vars["purpose"] != nil {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestCleanPurposeKeepsItWithinTheVaultLimit(t *testing.T) {
	long := strings.Repeat("é", 250)
	if got := CleanPurpose(long); len([]rune(got)) != MaxPurposeRunes {
		t.Fatalf("len = %d", len([]rune(got)))
	}
	if got := CleanPurpose(" \t\n\x01 "); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestNewRunIDIsFreshAndValid(t *testing.T) {
	a, b := NewRunID(), NewRunID()
	if a == b || !ValidRunID(a) || !ValidRunID(b) || !strings.HasPrefix(a, "run_") {
		t.Fatalf("a=%q b=%q", a, b)
	}
	for _, bad := range []string{"", "run id", "run/1", strings.Repeat("a", 65), "rün"} {
		if ValidRunID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidRunID(strings.Repeat("a", 64)) || !ValidRunID("A-z_09") {
		t.Fatal("valid ids refused")
	}
}

func TestSecretUseRunListsTheRunsPendingUses(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"secretUseRun":[`+useJSON+`,`+useJSON+`]}}`, 200)
	uses, err := New(srv.URL, nil).SecretUseRun(context.Background(), "snk_u_x", "run_abc")
	if err != nil || len(uses) != 2 || cp.vars["runId"] != "run_abc" || !strings.Contains(cp.query, "secretUseRun(runId:$runId)") {
		t.Fatalf("uses=%+v err=%v query=%q vars=%#v", uses, err, cp.query, cp.vars)
	}
}
