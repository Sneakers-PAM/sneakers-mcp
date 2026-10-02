// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// checkGateway answers requestSecretCheck with requestBody and then serves the
// status bodies in order, repeating the last.
func checkGateway(t *testing.T, requestBody string, statuses ...string) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(req.Query, "requestSecretCheck") {
			_, _ = io.WriteString(w, requestBody)
			return
		}
		i := int(n.Add(1)) - 1
		if i >= len(statuses) {
			i = len(statuses) - 1
		}
		_, _ = io.WriteString(w, `{"data":{"secretCheckStatus":`+statuses[i]+`}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fastChecks(ts *toolset) *toolset {
	ts.checkPoll, ts.checkWait = time.Millisecond, 200*time.Millisecond
	return ts
}

func TestTestSecretWaitsForTheConnectorsAnswer(t *testing.T) {
	srv := checkGateway(t, `{"data":{"requestSecretCheck":1790000000}}`,
		`{"result":"OK","checkedAtUnix":1789990000,"detail":"","pending":true}`,
		`{"result":"FAILED","checkedAtUnix":1790000030,"detail":"LDAP bind: invalid credentials","pending":false}`)
	_, out, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err != nil || out.Pending || out.Result != "failed" || out.Detail != "LDAP bind: invalid credentials" || out.CheckedAtUnix != 1790000030 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestTestSecretReportsPendingWhenNoConnectorAnswers(t *testing.T) {
	srv := checkGateway(t, `{"data":{"requestSecretCheck":1790000000}}`,
		`{"result":"OK","checkedAtUnix":1789990000,"detail":"","pending":true}`)
	_, out, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err != nil || !out.Pending || !strings.Contains(out.Message, "connector") {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestTestSecretWhenRateLimitedReturnsTheLastResult(t *testing.T) {
	srv := checkGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = ResourceExhausted desc = a check was requested in the last minute; read the status instead"}]}`,
		`{"result":"OK","checkedAtUnix":1790000030,"detail":"","pending":false}`)
	_, out, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err != nil || out.Result != "ok" || !strings.Contains(out.Message, "minute") {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestTestSecretSurfacesARefusal(t *testing.T) {
	srv := checkGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = this secret has no heartbeat"}]}`, `{}`)
	if _, _, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"}); err == nil || !strings.Contains(err.Error(), "no heartbeat") {
		t.Fatalf("err = %v", err)
	}
}
