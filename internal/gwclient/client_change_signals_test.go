// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

const signalledSummary = `{"id":"s1","name":"svc","folderId":"f","typeId":"type-windows-domain",` +
	`"valueVersion":4,"valueChangedAt":"2026-10-01T12:00:00Z","rotationEnabled":true,"rotatesOnCheckin":true,"heartbeatEnabled":true,` +
	`"lastRotationResult":"OK","rotatedAt":"2026-10-01T12:00:00Z","nextRotationAt":"2026-10-31T12:00:00Z","lastHeartbeatResult":"OK"}`

func checkSignalled(t *testing.T, s *SecretSummary) {
	t.Helper()
	if s.ValueVersion != 4 || s.ValueChangedAt == nil || *s.ValueChangedAt != "2026-10-01T12:00:00Z" || !s.RotationEnabled || !s.RotatesOnCheckin ||
		!s.HeartbeatEnabled || s.LastRotationResult == nil || *s.LastRotationResult != "OK" || s.NextRotationAt == nil || s.LastHeartbeatResult == nil {
		t.Fatalf("summary = %+v", s)
	}
}

func TestFindSecretsChangedSinceSendsTheFilterAndDecodesTheSignals(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"findSecretsForPrincipal":[`+signalledSummary+`]}}`, 200)
	out, err := New(srv.URL, nil).FindSecretsChangedSince(context.Background(), "tok", "", "", "", "2026-10-01T00:00:00Z")
	if err != nil || len(out) != 1 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if cp.vars["changedSince"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("changedSince = %#v", cp.vars["changedSince"])
	}
	checkSignalled(t, &out[0])

	if _, err := New(srv.URL, nil).FindSecrets(context.Background(), "tok", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if v, ok := cp.vars["changedSince"]; !ok || v != nil {
		t.Fatalf("FindSecrets changedSince = %#v (present=%v), want explicit null", v, ok)
	}
}

func TestGetSecretReturnsTheSummary(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"secretForPrincipal":`+signalledSummary+`}}`, 200)
	s, err := New(srv.URL, nil).GetSecret(context.Background(), "tok", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if cp.vars["id"] != "s1" || !strings.Contains(cp.query, "secretForPrincipal(id:$id)") {
		t.Fatalf("vars=%#v query=%s", cp.vars, cp.query)
	}
	checkSignalled(t, s)
}

func TestEverySummarySelectionAsksForTheChangeSignals(t *testing.T) {
	for name, q := range map[string]string{"find": findQuery, "get": getSecretQuery, "create": createQuery, "generate": generateQuery, "move": moveQuery} {
		if !strings.Contains(q, "valueVersion valueChangedAt rotationEnabled rotatesOnCheckin heartbeatEnabled") {
			t.Errorf("%s query does not select the change signals: %s", name, q)
		}
	}
}
