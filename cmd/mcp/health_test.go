// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/health"
	"github.com/rs/zerolog"
)

type fakeDeps struct {
	gateway, jwks atomic.Int32
	paths         chan string
	srv           *httptest.Server
}

func newFakeDeps(t *testing.T) *fakeDeps {
	f := &fakeDeps{paths: make(chan string, 64)}
	f.gateway.Store(http.StatusOK)
	f.jwks.Store(http.StatusOK)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case f.paths <- r.URL.Path + "|" + r.Header.Get("Authorization"):
		default:
		}
		switch r.URL.Path {
		case "/readyz":
			w.WriteHeader(int(f.gateway.Load()))
		case "/.well-known/jwks.json":
			w.WriteHeader(int(f.jwks.Load()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func probe(t *testing.T, h http.Handler, path string) (int, health.Report) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var r health.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r
}

func depByName(r health.Report, name string) health.DepState {
	for _, d := range r.Dependencies {
		if d.Name == name {
			return d
		}
	}
	return health.DepState{}
}

func TestHealth_GatewayIsRequiredAndCheckedWithoutAToken(t *testing.T) {
	f := newFakeDeps(t)
	now := time.Unix(1_800_000_000, 0)
	c := newHealthChecker(config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true}, zerolog.Nop())
	c.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	mountHealth(mux, c)

	code, r := probe(t, mux, "/readyz")
	if code != http.StatusOK || depByName(r, "gateway").State != health.StateOK || !depByName(r, "gateway").Required {
		t.Fatalf("up: %d %+v", code, r)
	}
	if got := <-f.paths; got != "/readyz|" {
		t.Fatalf("gateway probe = %q, want GET /readyz without a token", got)
	}
	if len(r.Dependencies) != 1 {
		t.Fatalf("API tokens only: want just the gateway, got %+v", r.Dependencies)
	}

	f.gateway.Store(http.StatusServiceUnavailable)
	now = now.Add(health.CacheTTL)
	if code, r := probe(t, mux, "/readyz"); code != http.StatusServiceUnavailable || depByName(r, "gateway").State != health.StateDown {
		t.Fatalf("gateway not ready: %d %+v", code, r)
	}
	if code, _ := probe(t, mux, "/livez"); code != http.StatusOK {
		t.Fatalf("livez = %d, want 200 while the gateway is down", code)
	}

	f.gateway.Store(http.StatusOK)
	now = now.Add(health.CacheTTL)
	if code, _ := probe(t, mux, "/readyz"); code != http.StatusOK {
		t.Fatalf("recovered: %d", code)
	}

	f.srv.Close()
	now = now.Add(health.CacheTTL)
	if code, r := probe(t, mux, "/readyz"); code != http.StatusServiceUnavailable || depByName(r, "gateway").Error != health.ClassRefused {
		t.Fatalf("gateway stopped: %d %+v", code, r)
	}
}

func TestHealth_HydraJWKSRequiredOnlyWhenItIsTheOnlyBearerMode(t *testing.T) {
	f := newFakeDeps(t)
	now := time.Unix(1_800_000_000, 0)
	jwks := f.srv.URL + "/.well-known/jwks.json"
	f.jwks.Store(http.StatusBadGateway)

	both := newHealthChecker(config{GatewayURL: f.srv.URL + "/machine/graphql", HydraIssuer: "https://hydra.example.test/", HydraJWKSURL: jwks, AcceptAPITokens: true}, zerolog.Nop())
	both.Now = func() time.Time { return now }
	if r := both.Report(t.Context()); r.Status != health.StateDegraded || depByName(r, "hydra-jwks").State != health.StateDegraded {
		t.Fatalf("with API tokens on, a JWKS outage only degrades: %+v", r)
	}

	only := newHealthChecker(config{GatewayURL: f.srv.URL + "/machine/graphql", HydraIssuer: "https://hydra.example.test/", HydraJWKSURL: jwks}, zerolog.Nop())
	only.Now = func() time.Time { return now }
	if r := only.Report(t.Context()); r.Status != health.StateDown || !depByName(r, "hydra-jwks").Required {
		t.Fatalf("Hydra-only, a JWKS outage is down: %+v", r)
	}
}

func TestHealth_RoutesAreOutsideAuthAndHealthIsUnchanged(t *testing.T) {
	f := newFakeDeps(t)
	h, err := buildHandler(config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/livez", "/readyz", "/health"} {
		if code, _ := probe(t, h, p); code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 without a bearer", p, code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["status"] != "ok" || body["version"] == "" || body["commit"] == "" {
		t.Fatalf("/health = %s", rec.Body.String())
	}
}
