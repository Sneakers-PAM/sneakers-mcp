// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func readyz(t *testing.T, c *Checker) (int, Report) {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Readyz().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var r Report
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("readyz body: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, r
}

func livez(c *Checker) int {
	rec := httptest.NewRecorder()
	c.Livez().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/livez", nil))
	return rec.Code
}

func TestRequiredDependencyDownFailsReadinessNotLiveness(t *testing.T) {
	var down atomic.Bool
	calls := atomic.Int32{}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c := &Checker{Now: clk.now, Deps: []Dep{{Name: "gateway", Required: true, Check: func(context.Context) error {
		calls.Add(1)
		if down.Load() {
			return errors.New("dial tcp gw.example.test:9100: secret-text-SHOULD-NOT-LEAK")
		}
		return nil
	}}}}

	if code, r := readyz(t, c); code != http.StatusOK || r.Status != StateOK {
		t.Fatalf("up: %d %+v", code, r)
	}
	down.Store(true)
	if code, _ := readyz(t, c); code != http.StatusOK {
		t.Fatalf("inside the cache window the old answer stands, got %d", code)
	}
	if calls.Load() != 1 {
		t.Fatalf("checks = %d, want 1 (cached)", calls.Load())
	}
	clk.advance(CacheTTL)
	code, r := readyz(t, c)
	if code != http.StatusServiceUnavailable || r.Status != StateDown || r.Dependencies[0].State != StateDown || r.Dependencies[0].Error != ClassError {
		t.Fatalf("down: %d %+v", code, r)
	}
	if livez(c) != http.StatusOK {
		t.Fatal("liveness must not follow a dependency")
	}
	rec := httptest.NewRecorder()
	c.Readyz().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if body := rec.Body.String(); strings.Contains(body, "SHOULD-NOT-LEAK") || strings.Contains(body, "example.test") {
		t.Fatalf("error text reached the body: %s", body)
	}
	down.Store(false)
	clk.advance(CacheTTL)
	if code, r := readyz(t, c); code != http.StatusOK || r.Status != StateOK {
		t.Fatalf("recovered: %d %+v", code, r)
	}
}

func TestOptionalDependencyDegrades(t *testing.T) {
	c := &Checker{Deps: []Dep{
		{Name: "gateway", Required: true, Check: func(context.Context) error { return nil }},
		{Name: "hydra-jwks", Check: func(context.Context) error { return &StatusError{Code: 500} }},
	}}
	code, r := readyz(t, c)
	if code != http.StatusOK || r.Status != StateDegraded || r.Dependencies[1].State != StateDegraded {
		t.Fatalf("got %d %+v", code, r)
	}
}

func TestCheckTimesOut(t *testing.T) {
	c := &Checker{Timeout: 20 * time.Millisecond, Deps: []Dep{{Name: "gateway", Required: true, Check: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}}
	if _, r := readyz(t, c); r.Dependencies[0].Error != ClassTimeout {
		t.Fatalf("got %+v", r)
	}
}

func TestHTTPCheckAgainstAStoppedServer(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	check := HTTP(srv.Client(), srv.URL+"/readyz")
	if err := check(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	status.Store(http.StatusUnauthorized)
	if got := Classify(check(context.Background())); got != ClassUnauthenticated {
		t.Fatalf("401 class = %q", got)
	}
	srv.Close()
	if got := Classify(check(context.Background())); got != ClassRefused {
		t.Fatalf("stopped server class = %q, want refused", got)
	}
}
