// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// capture records what the client sent so tests can assert on it.
type capture struct {
	auth  string
	query string
	vars  map[string]any
	calls atomic.Int32
}

func newFakeGateway(t *testing.T, cp *capture, respBody string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cp.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)
		cp.auth, cp.query, cp.vars = r.Header.Get("Authorization"), req.Query, req.Variables
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRevealFieldForwardsBearerAndReturnsValue(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"revealSecretFieldForPrincipal":"hunter2"}}`, 200)

	got, err := New(srv.URL, nil).RevealField(context.Background(), "tok-123", "sec-1", "password")
	if err != nil {
		t.Fatalf("RevealField: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("value = %q, want \"hunter2\"", got)
	}
	if cp.auth != "Bearer tok-123" {
		t.Fatalf("forwarded Authorization = %q, want the caller's token as a Bearer", cp.auth)
	}
	if !strings.Contains(cp.query, "revealSecretFieldForPrincipal") {
		t.Fatalf("query did not call revealSecretFieldForPrincipal: %s", cp.query)
	}
	if cp.vars["id"] != "sec-1" || cp.vars["fieldKey"] != "password" {
		t.Fatalf("variables = %v", cp.vars)
	}
}

func TestEmptyTokenNeverReachesGateway(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"revealSecretFieldForPrincipal":"leaked"}}`, 200)

	if _, err := New(srv.URL, nil).RevealField(context.Background(), "  ", "s", "f"); !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	if cp.calls.Load() != 0 {
		t.Fatal("the gateway must not be called without a token")
	}
}

func TestGraphQLErrorsBecomeGoErrors(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":null,"errors":[{"message":"not permitted to read this secret"}]}`, 200)

	_, err := New(srv.URL, nil).RevealField(context.Background(), "t", "sec-1", "password")
	if err == nil {
		t.Fatal("a GraphQL errors[] payload must surface as an error, not an empty success")
	}
	var ge *GraphQLError
	if !errors.As(err, &ge) {
		t.Fatalf("want *GraphQLError, got %T", err)
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("error should carry the gateway message, got: %v", err)
	}
}

func TestNon200BecomesStatusErrorWithoutBody(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `unauthorized body-marker`, 401)

	_, err := New(srv.URL, nil).RevealField(context.Background(), "bad", "s", "f")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 401 {
		t.Fatalf("err = %v, want *StatusError{401}", err)
	}
	if strings.Contains(err.Error(), "body-marker") {
		t.Fatal("the gateway's response body must not be echoed into errors")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var sawAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"data":{"revealSecretFieldForPrincipal":"x"}}`)
	}))
	t.Cleanup(target.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)

	if _, err := New(redir.URL, nil).RevealField(context.Background(), "t", "s", "f"); err == nil {
		t.Fatal("a redirect must be an error, never followed with the bearer")
	}
	if sawAuth.Load() != nil {
		t.Fatal("redirect target was contacted")
	}
}

func TestMissingDataIsAnError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":null}`, 200)

	if _, err := New(srv.URL, nil).RevealField(context.Background(), "t", "s", "f"); err == nil {
		t.Fatal("null data with no errors must not look like a successful empty value")
	}
}

func TestOversizedResponseIsRejected(t *testing.T) {
	var cp capture
	big := `{"data":{"revealSecretFieldForPrincipal":"` + strings.Repeat("a", maxResponseBytes+10) + `"}}`
	srv := newFakeGateway(t, &cp, big, 200)

	if _, err := New(srv.URL, nil).RevealField(context.Background(), "t", "s", "f"); err == nil {
		t.Fatal("responses larger than the cap must be rejected")
	}
}

func TestFindSecretsDecodesSummariesAndSendsNullForEmptyFilters(t *testing.T) {
	var cp capture
	body := `{"data":{"findSecretsForPrincipal":[{"id":"s1","name":"n1","folderId":"f1","typeId":"t1","targetId":null}]}}`
	srv := newFakeGateway(t, &cp, body, 200)

	out, err := New(srv.URL, nil).FindSecrets(context.Background(), "t", "q", "", "")
	if err != nil {
		t.Fatalf("FindSecrets: %v", err)
	}
	if len(out) != 1 || out[0].ID != "s1" || out[0].TargetID != nil {
		t.Fatalf("decoded = %+v, want one summary s1 with nil targetId", out)
	}
	if cp.vars["query"] != "q" {
		t.Fatalf("query variable = %v, want \"q\"", cp.vars["query"])
	}
	if v, ok := cp.vars["folderId"]; !ok || v != nil {
		t.Fatalf("folderId = %v (present=%v), want explicit null", v, ok)
	}
}

func TestCreateSecretSendsFieldsArray(t *testing.T) {
	var cp capture
	body := `{"data":{"createSecretForPrincipal":{"id":"s2","name":"svc","folderId":"f","typeId":"t","targetId":"tg"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	s, err := New(srv.URL, nil).CreateSecret(context.Background(), "t", "f", "t", "svc", nil, "tg")
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if s.ID != "s2" || s.TargetID == nil || *s.TargetID != "tg" {
		t.Fatalf("got %+v", s)
	}
	if arr, ok := cp.vars["fields"].([]any); !ok || len(arr) != 0 {
		t.Fatalf("fields = %#v, want an empty JSON array (never null)", cp.vars["fields"])
	}
}

func TestGenerateSecretReturnsSummaryAndValue(t *testing.T) {
	var cp capture
	body := `{"data":{"generateSecretForPrincipal":{"secret":{"id":"s9","name":"svc","folderId":"f","typeId":"t"},"generatedValue":"gen-pw"}}}`
	srv := newFakeGateway(t, &cp, body, 200)

	sum, val, err := New(srv.URL, nil).GenerateSecret(context.Background(), "t", "f", "t", "svc", nil, "", "", true)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if sum == nil || sum.ID != "s9" || val != "gen-pw" {
		t.Fatalf("got %+v / %q, want s9 / gen-pw", sum, val)
	}
	if cp.vars["returnValue"] != true {
		t.Fatalf("returnValue = %v, want true", cp.vars["returnValue"])
	}
}
