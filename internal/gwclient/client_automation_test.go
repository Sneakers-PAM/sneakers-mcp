// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const optedOutSummary = `{"id":"s1","name":"recovery-admin","folderId":"f","typeId":"type-windows-local","rotationOptOut":true,"heartbeatOptOut":false}`

func TestSummariesDecodeTheAutomationOptOuts(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"findSecretsForPrincipal":[`+optedOutSummary+`]}}`, 200)

	out, err := New(srv.URL, nil).FindSecrets(context.Background(), "tok", "", "", "")
	if err != nil || len(out) != 1 || !out[0].RotationOptOut || out[0].HeartbeatOptOut {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if !strings.Contains(cp.query, "rotationOptOut") || !strings.Contains(cp.query, "heartbeatOptOut") {
		t.Fatalf("find does not ask for the opt-outs: %s", cp.query)
	}
}

// Every operation that returns a SecretSummary asks for the same fields, so
// no result silently drops the opt-out state.
func TestEverySummarySelectionAsksForTheOptOuts(t *testing.T) {
	for name, q := range map[string]string{
		"find": findQuery, "create": createQuery, "generate": generateQuery, "move": moveQuery,
		"change type": changeTypeQuery, "set target": setSecretTargetMutation, "rename": renameSecretMutation,
		"set automation": setAutomationMutation,
	} {
		if !strings.Contains(q, "rotationOptOut heartbeatOptOut") {
			t.Errorf("%s query does not select the opt-outs: %s", name, q)
		}
	}
}

func TestCreateAndGenerateSendTheOptOutsOnlyWhenSet(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"createSecretForPrincipal":`+optedOutSummary+`}}`, 200)
	c := New(srv.URL, nil)

	s, err := c.CreateSecret(context.Background(), "tok", "f", "t", "recovery-admin", nil, "", Automation{DisableRotation: true})
	if err != nil || !s.RotationOptOut {
		t.Fatalf("s=%+v err=%v", s, err)
	}
	if cp.vars["disableRotation"] != true {
		t.Fatalf("disableRotation = %#v, want true", cp.vars["disableRotation"])
	}
	if v, ok := cp.vars["disableHeartbeat"]; !ok || v != nil {
		t.Fatalf("disableHeartbeat = %#v (present=%v), want explicit null", v, ok)
	}

	if _, err := c.CreateSecret(context.Background(), "tok", "f", "t", "svc", nil, ""); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"disableRotation", "disableHeartbeat"} {
		if v, ok := cp.vars[k]; !ok || v != nil {
			t.Fatalf("%s = %#v (present=%v), want explicit null by default", k, v, ok)
		}
	}

	srv2 := newFakeGateway(t, &cp, `{"data":{"generateSecretForPrincipal":{"secret":`+optedOutSummary+`,"generatedValue":null}}}`, 200)
	g, _, err := New(srv2.URL, nil).GenerateSecret(context.Background(), "tok", "f", "t", "recovery-admin", nil, "", "", false,
		Automation{DisableRotation: true, DisableHeartbeat: true})
	if err != nil || !g.RotationOptOut {
		t.Fatalf("g=%+v err=%v", g, err)
	}
	if cp.vars["disableRotation"] != true || cp.vars["disableHeartbeat"] != true {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestSetSecretAutomationSendsBothFlags(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"setSecretAutomationForPrincipal":`+optedOutSummary+`}}`, 200)

	s, err := New(srv.URL, nil).SetSecretAutomation(context.Background(), "tok", "s1", true, false)
	if err != nil || s.ID != "s1" || !s.RotationOptOut || s.HeartbeatOptOut {
		t.Fatalf("s=%+v err=%v", s, err)
	}
	if cp.auth != "Bearer tok" || !strings.Contains(cp.query, "setSecretAutomationForPrincipal") {
		t.Fatalf("auth=%q query=%q", cp.auth, cp.query)
	}
	if cp.vars["secretId"] != "s1" || cp.vars["disableRotation"] != true || cp.vars["disableHeartbeat"] != false {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestSetSecretAutomationDenialIsAGraphQLError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":null,"errors":[{"message":"not permitted to change this secret"}]}`, 200)
	var ge *GraphQLError
	if _, err := New(srv.URL, nil).SetSecretAutomation(context.Background(), "tok", "s1", true, true); !errors.As(err, &ge) {
		t.Fatalf("err = %v", err)
	}
}
