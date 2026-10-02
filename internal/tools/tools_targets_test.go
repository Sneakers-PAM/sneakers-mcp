// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strings"
	"testing"
)

func TestListConnectionsTool(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"connectionsForPrincipal":[{"id":"conn-ldaps","name":"AD LDAPS","protocol":"ldap","port":636,"useTls":true,"targetCount":2}]}}`)
	_, out, err := newTools(gw.URL, nil).listConnections(context.Background(), callReq("Bearer t"), listConnectionsIn{})
	if err != nil || len(out.Connections) != 1 || out.Connections[0].Port != 636 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestListTargetsToolForwardsFilters(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"targetsForPrincipal":[{"id":"t1","name":"ad DCs","hostname":"dc1.ad.example.org","kind":"windows","domain":"ad.example.org","realm":"","connectionId":"conn-ldaps","description":"","ownerUserId":"","secretCount":1}]}}`)
	_, out, err := newTools(gw.URL, nil).listTargets(context.Background(), callReq("Bearer t"), listTargetsIn{Query: "ad", ConnectionID: "conn-ldaps"})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || len(out.Targets) != 1 || !out.Targets[0].Shared || vars["query"] != "ad" || vars["connectionId"] != "conn-ldaps" {
		t.Fatalf("out=%+v err=%v vars=%#v", out, err, vars)
	}
}

func TestSaveTargetToolValidatesAndForwards(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"saveTargetForPrincipal":{"id":"t9","name":"branch DCs","hostname":"dc1.branch.example.org","kind":"windows","domain":"branch.example.org","realm":"","connectionId":"conn-ldaps","description":"","ownerUserId":"u-ada","secretCount":0}}}`)
	ts := newTools(gw.URL, nil)
	for name, host := range map[string]string{"space": "dc1 example", "scheme": "ldaps://dc1", "empty label": "dc1..org", "too long": strings.Repeat("a", 254)} {
		if _, _, err := ts.saveTarget(context.Background(), callReq("Bearer t"), saveTargetIn{Name: "x", Hostname: host, ConnectionID: "conn-ldaps"}); err == nil {
			t.Errorf("%s hostname %q accepted", name, host)
		}
	}
	if gw.calls.Load() != 0 {
		t.Fatal("an invalid hostname reached the gateway")
	}
	for _, host := range []string{"dc1.branch.example.org", "192.0.2.10", "2001:db8::1"} {
		_, out, err := ts.saveTarget(context.Background(), callReq("Bearer t"), saveTargetIn{Name: "branch DCs", Hostname: host, Kind: "windows", Domain: "branch.example.org", ConnectionID: "conn-ldaps"})
		if err != nil || out.Target.ID != "t9" || out.Target.Shared {
			t.Fatalf("host %q: out=%+v err=%v", host, out, err)
		}
	}
}

func TestSetSecretTargetTool(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"setSecretTargetForPrincipal":{"id":"s1","name":"da","folderId":"f","typeId":"t","targetId":"t1"}}}`)
	_, out, err := newTools(gw.URL, nil).setSecretTarget(context.Background(), callReq("Bearer t"), setSecretTargetIn{SecretID: "s1", TargetID: "t1"})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || out.Secret.ID != "s1" || vars["targetId"] != "t1" {
		t.Fatalf("out=%+v err=%v vars=%#v", out, err, vars)
	}
}

func TestTargetToolDenialsSurfaceAsToolErrors(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = PermissionDenied desc = not permitted to use this target"}]}`)
	_, _, err := newTools(gw.URL, nil).setSecretTarget(context.Background(), callReq("Bearer t"), setSecretTargetIn{SecretID: "s1", TargetID: "t-bob"})
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("err = %v", err)
	}
}
