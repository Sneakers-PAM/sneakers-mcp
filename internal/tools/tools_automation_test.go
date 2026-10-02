// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strings"
	"testing"
)

const optedOut = `{"id":"s1","name":"recovery-admin","folderId":"f","typeId":"type-windows-local","rotationOptOut":true,"heartbeatOptOut":true}`

func TestFindSecretsShowsTheOptOuts(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"findSecretsForPrincipal":[`+optedOut+`]}}`)
	_, out, err := newTools(gw.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{})
	if err != nil || len(out.Secrets) != 1 || !out.Secrets[0].RotationOptOut || !out.Secrets[0].HeartbeatOptOut {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCreateAndGenerateForwardTheOptOuts(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":`+optedOut+`}}`)
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"),
		createSecretIn{FolderID: "f", TypeID: "type-windows-local", Name: "recovery-admin", DisableRotation: true, DisableHeartbeat: true})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || !out.Secret.RotationOptOut || vars["disableRotation"] != true || vars["disableHeartbeat"] != true {
		t.Fatalf("create: out=%+v err=%v vars=%#v", out, err, vars)
	}

	gw2 := fakeGateway(t, `{"data":{"generateSecretForPrincipal":{"secret":`+optedOut+`,"generatedValue":null}}}`)
	_, gout, err := newTools(gw2.URL, nil).generateSecret(context.Background(), callReq("Bearer t"),
		generateSecretIn{FolderID: "f", TypeID: "type-windows-local", Name: "recovery-admin", DisableRotation: true})
	vars, _ = gw2.vars.Load().(map[string]any)
	if err != nil || !gout.Secret.RotationOptOut || vars["disableRotation"] != true || vars["disableHeartbeat"] != nil {
		t.Fatalf("generate: out=%+v err=%v vars=%#v", gout, err, vars)
	}
}

func TestSetSecretAutomationToolForwardsBothFlags(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"setSecretAutomationForPrincipal":`+optedOut+`}}`)
	_, out, err := newTools(gw.URL, nil).setSecretAutomation(context.Background(), callReq("Bearer agent-tok"),
		setSecretAutomationIn{ID: "s1", DisableRotation: true, DisableHeartbeat: false})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || out.Secret.ID != "s1" || !out.Secret.RotationOptOut {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if gw.gotAuth() != "Bearer agent-tok" || vars["secretId"] != "s1" || vars["disableRotation"] != true || vars["disableHeartbeat"] != false {
		t.Fatalf("auth=%q vars=%#v", gw.gotAuth(), vars)
	}
}

func TestSetSecretAutomationDenialsSurfaceAsToolErrors(t *testing.T) {
	for _, msg := range []string{
		"rpc error: code = PermissionDenied desc = not permitted to change this secret",
		"rpc error: code = NotFound desc = secret not found",
	} {
		gw := fakeGateway(t, `{"data":null,"errors":[{"message":"`+msg+`"}]}`)
		_, out, err := newTools(gw.URL, nil).setSecretAutomation(context.Background(), callReq("Bearer t"), setSecretAutomationIn{ID: "s1", DisableRotation: true})
		want := msg[strings.Index(msg, "desc = ")+len("desc = "):]
		if err == nil || !strings.Contains(err.Error(), want) || out.Secret.ID != "" {
			t.Fatalf("err=%v out=%+v", err, out)
		}
	}
}

func TestSetSecretAutomationRefusesBadIDsBeforeCallingGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	for name, id := range map[string]string{"missing": "", "blank": "  ", "too long": strings.Repeat("x", maxIDLen+1)} {
		if _, _, err := ts.setSecretAutomation(context.Background(), callReq("Bearer t"), setSecretAutomationIn{ID: id}); err == nil {
			t.Errorf("%s id accepted", name)
		}
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times for invalid input", gw.calls.Load())
	}
}

func TestCreateAndGenerateDescriptionsSteerNeverRotatingCredentials(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolCreate && tl.Name != toolGenerate {
			continue
		}
		if !strings.Contains(tl.Description, "disableRotation") || !strings.Contains(tl.Description, "a recovery password") {
			t.Errorf("%s description does not steer never-rotating credentials to disableRotation: %q", tl.Name, tl.Description)
		}
	}
}
