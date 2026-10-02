// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// whoamiGateway answers the pre-check with or without machineWhoami support.
func whoamiGateway(t *testing.T, supportsWhoami bool, whoami string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		b, _ := io.ReadAll(r.Body)
		asksWhoami := strings.Contains(string(b), "machineWhoami")
		switch {
		case asksWhoami && !supportsWhoami:
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"errors":[{"message":"Cannot query field \"machineWhoami\" on type \"Query\"."}],"data":null}`)
		case asksWhoami:
			_, _ = io.WriteString(w, `{"data":{"machineHealth":true,"machineWhoami":`+whoami+`}}`)
		default:
			_, _ = io.WriteString(w, `{"data":{"machineHealth":true}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestPersonalTokenIsLabelledAsAUserTokenWithItsOwner(t *testing.T) {
	srv, _ := whoamiGateway(t, true, `{"kind":"user_token","userId":"u-ada","principalId":"utok-1"}`)
	v := newVerifier(t, srv.URL, nil)
	tok := userTokenPrefix + newToken(t)
	info, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.UserID, "user-token:u-ada:") || strings.Contains(info.UserID, tok) {
		t.Fatalf("label = %q, want user-token:u-ada:<fingerprint>", info.UserID)
	}
	again, err := v.Verify(context.Background(), tok)
	if err != nil || again.UserID != info.UserID {
		t.Fatalf("cached label = %q, %v; want %q", again.UserID, err, info.UserID)
	}
}

func TestServiceAccountTokenIsLabelledWithItsAccount(t *testing.T) {
	srv, _ := whoamiGateway(t, true, `{"kind":"service_account","userId":"","principalId":"sa-backup"}`)
	info, err := newVerifier(t, srv.URL, nil).Verify(context.Background(), newToken(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.UserID, "sa-token:sa-backup:") {
		t.Fatalf("label = %q, want sa-token:sa-backup:<fingerprint>", info.UserID)
	}
}

func TestOlderGatewayStillAuthenticatesAndLabelsByKind(t *testing.T) {
	srv, calls := whoamiGateway(t, false, "")
	info, err := newVerifier(t, srv.URL, nil).Verify(context.Background(), userTokenPrefix+newToken(t))
	if err != nil {
		t.Fatalf("an older gateway must still authenticate: %v", err)
	}
	if !strings.HasPrefix(info.UserID, "user-token:") || strings.HasPrefix(info.UserID, "sa-token:") {
		t.Fatalf("label = %q, want a user-token label", info.UserID)
	}
	if calls.Load() != 2 {
		t.Fatalf("gateway calls = %d, want the whoami attempt plus one health-only retry", calls.Load())
	}
}
