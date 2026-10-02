// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestListConnections(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"connectionsForPrincipal":[{"id":"conn-ldaps","name":"AD LDAPS","protocol":"ldap","port":636,"useTls":true,"targetCount":2}]}}`, 200)
	cs, err := New(srv.URL, nil).ListConnections(context.Background(), "tok")
	if err != nil || len(cs) != 1 || cs[0].Port != 636 || !cs[0].UseTLS || !strings.Contains(cp.query, "connectionsForPrincipal") {
		t.Fatalf("cs=%+v err=%v query=%q", cs, err, cp.query)
	}
}

func TestListTargetsSendsFilters(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"targetsForPrincipal":[{"id":"t1","name":"ad DCs","hostname":"dc1.ad.example.org","kind":"windows","domain":"ad.example.org","realm":"","connectionId":"conn-ldaps","description":"","ownerUserId":"","secretCount":1}]}}`, 200)
	ts, err := New(srv.URL, nil).ListTargets(context.Background(), "tok", "ad", "conn-ldaps")
	if err != nil || len(ts) != 1 || ts[0].Domain != "ad.example.org" || cp.vars["query"] != "ad" || cp.vars["connectionId"] != "conn-ldaps" {
		t.Fatalf("ts=%+v err=%v vars=%#v", ts, err, cp.vars)
	}
}

func TestSaveTargetSendsTheInput(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"saveTargetForPrincipal":{"id":"t9","name":"branch DCs","hostname":"dc1.branch.example.org","kind":"windows","domain":"branch.example.org","realm":"BRANCH.EXAMPLE.ORG","connectionId":"conn-ldaps","description":"","ownerUserId":"u-ada","secretCount":0}}}`, 200)
	tg, err := New(srv.URL, nil).SaveTarget(context.Background(), "tok", TargetInput{
		Name: "branch DCs", Hostname: "dc1.branch.example.org", Kind: "windows", Domain: "branch.example.org", Realm: "BRANCH.EXAMPLE.ORG", ConnectionID: "conn-ldaps",
	})
	in, _ := cp.vars["input"].(map[string]any)
	if err != nil || tg.ID != "t9" || tg.OwnerUserID != "u-ada" || in["hostname"] != "dc1.branch.example.org" || in["connectionId"] != "conn-ldaps" {
		t.Fatalf("tg=%+v err=%v input=%#v", tg, err, in)
	}
	if _, set := in["id"]; set {
		t.Fatal("a create must not send an id")
	}
}

func TestSetSecretTargetAttachesAndDetaches(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"setSecretTargetForPrincipal":{"id":"s1","name":"da","folderId":"f","typeId":"t","targetId":"t1"}}}`, 200)
	c := New(srv.URL, nil)
	s, err := c.SetSecretTarget(context.Background(), "tok", "s1", "t1")
	if err != nil || s.TargetID == nil || *s.TargetID != "t1" || cp.vars["secretId"] != "s1" || cp.vars["targetId"] != "t1" {
		t.Fatalf("s=%+v err=%v vars=%#v", s, err, cp.vars)
	}
	if _, err := c.SetSecretTarget(context.Background(), "tok", "s1", ""); err != nil || cp.vars["targetId"] != nil {
		t.Fatalf("detach err=%v vars=%#v", err, cp.vars)
	}
}

func TestRequestSecretCheckAndStatus(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"requestSecretCheck":1790000000}}`, 200)
	at, err := New(srv.URL, nil).RequestSecretCheck(context.Background(), "tok", "s1")
	if err != nil || at != 1790000000 || cp.vars["secretId"] != "s1" {
		t.Fatalf("at=%d err=%v vars=%#v", at, err, cp.vars)
	}
	srv2 := newFakeGateway(t, &cp, `{"data":{"secretCheckStatus":{"result":"FAILED","checkedAtUnix":1790000030,"detail":"invalid credentials","pending":false}}}`, 200)
	st, err := New(srv2.URL, nil).SecretCheckStatus(context.Background(), "tok", "s1")
	if err != nil || st.Result != "FAILED" || st.CheckedAtUnix != 1790000030 || st.Detail != "invalid credentials" {
		t.Fatalf("st=%+v err=%v", st, err)
	}
}
