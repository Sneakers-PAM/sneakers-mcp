// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestListTargetsReturnsHostKeys(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"targetsForPrincipal":[{"id":"t1","name":"web-01","hostname":"web-01.example.org","connectionId":"conn-ssh","sshHostKeys":["ssh-ed25519 pinned-1","ssh-rsa pinned-2"]}]}}`, 200)
	ts, err := New(srv.URL, nil).ListTargets(context.Background(), "tok", "", "")
	if err != nil || len(ts) != 1 || strings.Join(ts[0].SSHHostKeys, "|") != "ssh-ed25519 pinned-1|ssh-rsa pinned-2" {
		t.Fatalf("ts=%+v err=%v", ts, err)
	}
	if !strings.Contains(cp.query, "sshHostKeys") {
		t.Fatalf("query does not select sshHostKeys: %s", cp.query)
	}
}

func TestSaveTargetHostKeysOmittedSetOrCleared(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"saveTargetForPrincipal":{"id":"t9","name":"web-01","hostname":"web-01.example.org","connectionId":"conn-ssh","sshHostKeys":["ssh-ed25519 pinned-1"]}}}`, 200)
	c := New(srv.URL, nil)
	base := TargetInput{ID: "t9", Name: "web-01", Hostname: "web-01.example.org", ConnectionID: "conn-ssh"}

	if _, err := c.SaveTarget(context.Background(), "tok", base); err != nil {
		t.Fatal(err)
	}
	if in, _ := cp.vars["input"].(map[string]any); in == nil || in["sshHostKeys"] != nil {
		t.Fatalf("omitted host keys sent: %#v", cp.vars["input"])
	} else if _, set := in["sshHostKeys"]; set {
		t.Fatal("omitted host keys must leave the field out, so the gateway keeps the pins")
	}

	set := base
	keys := []string{"ssh-ed25519 pinned-1"}
	set.SSHHostKeys = &keys
	tg, err := c.SaveTarget(context.Background(), "tok", set)
	in, _ := cp.vars["input"].(map[string]any)
	got, _ := in["sshHostKeys"].([]any)
	if err != nil || len(got) != 1 || got[0] != "ssh-ed25519 pinned-1" || len(tg.SSHHostKeys) != 1 {
		t.Fatalf("tg=%+v err=%v input=%#v", tg, err, in)
	}

	clear := base
	none := []string{}
	clear.SSHHostKeys = &none
	if _, err := c.SaveTarget(context.Background(), "tok", clear); err != nil {
		t.Fatal(err)
	}
	in, _ = cp.vars["input"].(map[string]any)
	if got, ok := in["sshHostKeys"].([]any); !ok || len(got) != 0 {
		t.Fatalf("clearing must send [], input=%#v", in)
	}
}
