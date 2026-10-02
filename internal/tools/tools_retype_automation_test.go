// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"strings"
	"testing"
)

// The type-change result tells the agent what happened to rotation,
// heartbeat and the target, and what to do next.
func TestChangeSecretTypeReportsAutomation(t *testing.T) {
	cases := []struct {
		name, automation string
		wantNote         []string
	}{
		{"into AD without a target", `{"rotation":"OFF","heartbeat":"NO_TARGET","target":"NONE"}`,
			[]string{"Rotation is off", toolSetAutomation, "No heartbeat runs until a target is attached", "sneakers_set_secret_target"}},
		{"into AD with a target", `{"rotation":"OFF","heartbeat":"ON","target":"ATTACHED"}`,
			[]string{"Rotation is off", "Heartbeat checks run against the target", "The target was kept"}},
		{"out to a generic type", `{"rotation":"NONE","heartbeat":"NONE","target":"NOT_SUPPORTED"}`,
			[]string{"no rotation or heartbeat", "takes no target", "detached"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"t2"},"fieldKeys":["password"],"automation":`+tc.automation+`}}}`)
			_, out, err := newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "t2"})
			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			if out.Automation.Rotation == "" || out.Automation.Heartbeat == "" || out.Automation.Target == "" {
				t.Fatalf("automation not reported: %+v", out.Automation)
			}
			for _, w := range tc.wantNote {
				if !strings.Contains(out.Automation.Note, w) {
					t.Fatalf("note %q does not mention %q", out.Automation.Note, w)
				}
			}
		})
	}
}

func TestChangeSecretTypeDescriptionAllowsManagedTypes(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolRetype {
			continue
		}
		d := tl.Description
		if strings.Contains(d, "a human must") || strings.Contains(d, "are refused") && strings.Contains(d, "certificate type, and") {
			t.Fatalf("description still refuses managed types: %q", d)
		}
		for _, w := range []string{"rotation", "heartbeat", "certificate", "target", toolSetAutomation} {
			if !strings.Contains(d, w) {
				t.Fatalf("description must explain %q: %q", w, d)
			}
		}
		return
	}
	t.Fatal("tool not registered")
}

func TestChangeSecretTypeReportsMovedToNotesKeys(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"},"fieldKeys":["notes"],"movedToNotesKeys":["domain","netbios"],"automation":{"rotation":"NONE","heartbeat":"NONE","target":"NOT_SUPPORTED"}}}}`)
	_, out, err := newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "type-password"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if strings.Join(out.MovedToNotesKeys, ",") != "domain,netbios" {
		t.Fatalf("movedToNotesKeys = %v", out.MovedToNotesKeys)
	}

	gw = fakeGateway(t, `{"data":{"changeSecretTypeForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f","typeId":"type-password"},"fieldKeys":["notes"]}}}`)
	_, out, err = newTools(gw.URL, nil).changeSecretType(context.Background(), callReq("Bearer t"), changeSecretTypeIn{ID: "s1", NewTypeID: "type-password"})
	if err != nil || out.MovedToNotesKeys == nil {
		t.Fatalf("movedToNotesKeys must be a non-null list (err=%v)", err)
	}
}

func TestChangeSecretTypeDescriptionNamesMovedToNotesKeys(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name == toolRetype && !strings.Contains(tl.Description, "movedToNotesKeys") {
			t.Fatalf("description must name movedToNotesKeys: %q", tl.Description)
		}
	}
}
