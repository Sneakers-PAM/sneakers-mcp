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
)

const noConnectorReply = `{"data":null,"errors":[{"message":"rpc error: code = FailedPrecondition desc = no connector is available in this environment"}]}`

// countingCheckGateway answers requestSecretCheck with requestBody and counts
// secretCheckStatus calls, answering each with status.
func countingCheckGateway(t *testing.T, requestBody, status string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
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
		polls.Add(1)
		_, _ = io.WriteString(w, `{"data":{"secretCheckStatus":`+status+`}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &polls
}

func TestTestSecretWithNoConnectorSaysSoWithoutPolling(t *testing.T) {
	srv, polls := countingCheckGateway(t, noConnectorReply, `{"result":"OK","checkedAtUnix":1,"detail":"","pending":false}`)
	_, out, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := "No connector is available in this environment, so this credential can't be checked right now."
	if out.Available == nil || *out.Available || out.Message != want || out.Pending || out.Result != "" {
		t.Fatalf("out = %+v", out)
	}
	if n := polls.Load(); n != 0 {
		t.Fatalf("polled secretCheckStatus %d times", n)
	}
}

func TestTestSecretOtherRequestErrorsStayToolErrors(t *testing.T) {
	srv, polls := countingCheckGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = Unavailable desc = vault is down"}]}`, `{}`)
	_, _, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err == nil || !strings.Contains(err.Error(), "vault is down") || polls.Load() != 0 {
		t.Fatalf("err = %v polls = %d", err, polls.Load())
	}
}

func TestTestSecretNormalResultLeavesAvailabilityUnset(t *testing.T) {
	srv, _ := countingCheckGateway(t, `{"data":{"requestSecretCheck":1790000000}}`, `{"result":"OK","checkedAtUnix":1790000030,"detail":"","pending":false}`)
	_, out, err := fastChecks(newTools(srv.URL, nil)).testSecret(context.Background(), callReq("Bearer t"), testSecretIn{SecretID: "s1"})
	if err != nil || out.Result != "ok" || out.Available != nil {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestTestSecretDescriptionMentionsMissingConnector(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name == toolTestSecret {
			if !strings.Contains(tl.Description, "no connector") || !strings.Contains(tl.Description, "available") {
				t.Fatalf("description = %q", tl.Description)
			}
			return
		}
	}
	t.Fatal("tool not registered")
}
