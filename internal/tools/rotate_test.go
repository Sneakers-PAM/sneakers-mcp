// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strings"
	"testing"
)

// TestRotateSecretToolAlwaysReturnsTheNewValue proves rotateSecret bridges to
// the gateway's rotateSecretForPrincipal, forwarding the optional policyId
// and always returning the new value (unlike sneakers_generate_secret's
// opt-in returnValue).
func TestRotateSecretToolAlwaysReturnsTheNewValue(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"rotateSecretForPrincipal":{"secret":{"id":"s1","name":"host-a admin","folderId":"f","typeId":"t"},"newValue":"rotated-pw"}}}`)
	_, out, err := newTools(gw.URL, nil).rotateSecret(context.Background(), callReq("Bearer t"), rotateSecretIn{SecretID: "s1", PolicyID: "pol-1"})
	vars, _ := gw.vars.Load().(map[string]any)
	if err != nil || out.Secret.ID != "s1" || out.NewValue != "rotated-pw" || vars["policyId"] != "pol-1" {
		t.Fatalf("out=%+v err=%v vars=%#v", out, err, vars)
	}
}

// TestRotateSecretToolRefusedWhileRotationInProgressSurfacesAsError proves a
// vault refusal (e.g. ROTATION_IN_PROGRESS) surfaces as a tool error, not a
// silent empty result.
func TestRotateSecretToolRefusedWhileRotationInProgressSurfacesAsError(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = a rotation of this secret is queued or running"}]}`)
	_, _, err := newTools(gw.URL, nil).rotateSecret(context.Background(), callReq("Bearer t"), rotateSecretIn{SecretID: "s1"})
	if err == nil || !strings.Contains(err.Error(), "queued or running") {
		t.Fatalf("err = %v", err)
	}
}

// TestRestoreSecretVersionToolForwardsVersionNo proves restoreSecretVersion
// bridges straight to restoreSecretVersionForPrincipal.
func TestRestoreSecretVersionToolForwardsVersionNo(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"restoreSecretVersionForPrincipal":{"id":"s1","name":"host-a admin","folderId":"f","typeId":"t"}}}`)
	_, out, err := newTools(gw.URL, nil).restoreSecretVersion(context.Background(), callReq("Bearer t"), restoreSecretVersionIn{SecretID: "s1", VersionNo: 2})
	vars, _ := gw.vars.Load().(map[string]any)
	n, _ := vars["versionNo"].(float64)
	if err != nil || out.Secret.ID != "s1" || int(n) != 2 {
		t.Fatalf("out=%+v err=%v vars=%#v", out, err, vars)
	}
}

// TestRestoreSecretVersionToolRejectsNonPositiveVersion proves the tool
// refuses before calling the gateway when versionNo is less than 1.
func TestRestoreSecretVersionToolRejectsNonPositiveVersion(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	_, _, err := newTools(gw.URL, nil).restoreSecretVersion(context.Background(), callReq("Bearer t"), restoreSecretVersionIn{SecretID: "s1", VersionNo: 0})
	if err == nil || gw.calls.Load() != 0 {
		t.Fatalf("want a local validation error and no gateway call, err=%v calls=%d", err, gw.calls.Load())
	}
}
