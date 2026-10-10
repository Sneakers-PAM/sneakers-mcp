// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/rs/zerolog"
)

// testTTL is the cache window the tests run with; waiting it out lets the next
// probe run the checks again.
const testTTL = time.Second

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

// readyBody is the /readyz answer.
type readyBody struct {
	Status       health.State              `json:"status"`
	Ready        bool                      `json:"ready"`
	Build        buildinfo.Info            `json:"build"`
	Dependencies []health.DependencyReport `json:"dependencies"`
}

func probe(t *testing.T, h http.Handler, path string) (int, readyBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var r readyBody
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r
}

func depByName(r readyBody, name string) health.DependencyReport {
	for _, d := range r.Dependencies {
		if d.Name == name {
			return d
		}
	}
	return health.DependencyReport{}
}

func testChecker(t *testing.T, cfg config) *health.Checker {
	t.Helper()
	c, err := newHealthChecker(cfg, log.Nop(), health.WithTTL(testTTL))
	if err != nil {
		t.Fatal(err)
	}
	runChecker(t, c)
	return c
}

// runChecker runs c's background refresh, as buildHandler does, and waits for
// its first pass so reports hold real results instead of "pending".
func runChecker(t *testing.T, c *health.Checker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending := false
		for _, d := range c.Report(context.Background()).Dependencies {
			pending = pending || d.Error == health.ClassPending
		}
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the first background refresh never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// /readyz reads a cache refreshed in the background, so a gateway whose own
// /readyz hangs can't make the MCP probe wait (or time it out).
func TestHealth_ReadyzNeverWaitsOnTheGateway(t *testing.T) {
	var hang atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hang.Load() {
			select {
			case <-release:
			case <-time.After(3 * time.Second):
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(gw.Close)
	hangSoon := time.AfterFunc(500*time.Millisecond, func() { hang.Store(true) })
	t.Cleanup(func() { hangSoon.Stop() })
	mux, err := buildHandler(t.Context(), config{GatewayURL: gw.URL + "/machine/graphql", AcceptAPITokens: true}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for code, _ := probe(t, mux, "/readyz"); code != http.StatusOK; code, _ = probe(t, mux, "/readyz") {
		if time.Now().After(deadline) {
			t.Fatal("/readyz never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Past the 5 s cache, so a probe that ran the check itself would hang.
	time.Sleep(cacheTTL + time.Second)
	for range 5 {
		start := time.Now()
		probe(t, mux, "/readyz")
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("/readyz took %v while the gateway hangs, want a cache read", d)
		}
	}
}

func healthMux(t *testing.T, c *health.Checker) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	if err := mountHealth(mux, c); err != nil {
		t.Fatal(err)
	}
	return mux
}

func TestHealth_GatewayIsRequiredAndCheckedWithoutAToken(t *testing.T) {
	f := newFakeDeps(t)
	mux := healthMux(t, testChecker(t, config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true}))

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
	time.Sleep(2 * testTTL)
	if code, r := probe(t, mux, "/readyz"); code != http.StatusServiceUnavailable || depByName(r, "gateway").State != health.StateDown {
		t.Fatalf("gateway not ready: %d %+v", code, r)
	}
	if code, _ := probe(t, mux, "/livez"); code != http.StatusOK {
		t.Fatalf("livez = %d, want 200 while the gateway is down", code)
	}

	f.gateway.Store(http.StatusOK)
	time.Sleep(2 * testTTL)
	if code, _ := probe(t, mux, "/readyz"); code != http.StatusOK {
		t.Fatalf("recovered: %d", code)
	}

	f.srv.Close()
	time.Sleep(2 * testTTL)
	if code, r := probe(t, mux, "/readyz"); code != http.StatusServiceUnavailable || depByName(r, "gateway").Error != "refused" {
		t.Fatalf("gateway stopped: %d %+v", code, r)
	}
}

func TestHealth_HydraJWKSRequiredOnlyWhenItIsTheOnlyBearerMode(t *testing.T) {
	f := newFakeDeps(t)
	jwks := f.srv.URL + "/.well-known/jwks.json"
	f.jwks.Store(http.StatusBadGateway)

	both := testChecker(t, config{GatewayURL: f.srv.URL + "/machine/graphql", HydraIssuer: "https://hydra.example.test/", HydraJWKSURL: jwks, AcceptAPITokens: true})
	if r := both.Report(t.Context()); r.Status != health.StateDegraded || r.Dependencies[1].Name != "hydra-jwks" || r.Dependencies[1].State != health.StateDegraded {
		t.Fatalf("with API tokens on, a JWKS outage only degrades: %+v", r)
	}

	only := testChecker(t, config{GatewayURL: f.srv.URL + "/machine/graphql", HydraIssuer: "https://hydra.example.test/", HydraJWKSURL: jwks})
	if r := only.Report(t.Context()); r.Status != health.StateDown || r.Dependencies[1].Name != "hydra-jwks" || !r.Dependencies[1].Required {
		t.Fatalf("Hydra-only, a JWKS outage is down: %+v", r)
	}
}

func TestHealth_RoutesAreOutsideAuthAndHealthIsGone(t *testing.T) {
	f := newFakeDeps(t)
	h, err := buildHandler(t.Context(), config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/livez", "/readyz"} {
		// /readyz turns 200 once the first background check has passed.
		deadline := time.Now().Add(5 * time.Second)
		code, _ := probe(t, h, p)
		for code != http.StatusOK && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			code, _ = probe(t, h, p)
		}
		if code != http.StatusOK {
			t.Fatalf("%s = %d, want 200 without a bearer", p, code)
		}
	}
	if code, _ := probe(t, h, "/health"); code != http.StatusNotFound {
		t.Fatalf("/health = %d, want 404", code)
	}
}

// The checks below cover the readiness rules the server relies on, through
// its own checker and routes.

func TestHealth_RequiredDependencyDownFailsReadinessNotLiveness(t *testing.T) {
	var down atomic.Bool
	calls := atomic.Int32{}
	c := health.New(health.WithTTL(testTTL))
	if err := c.Register(health.Dependency{Name: "gateway", Required: true, Check: func(context.Context) error {
		calls.Add(1)
		if down.Load() {
			return errors.New("dial tcp gw.example.test:9100: secret-text-SHOULD-NOT-LEAK")
		}
		return nil
	}}); err != nil {
		t.Fatal(err)
	}
	mux := healthMux(t, c)

	if code, r := probe(t, mux, "/readyz"); code != http.StatusOK || r.Status != health.StateOK {
		t.Fatalf("up: %d %+v", code, r)
	}
	down.Store(true)
	if code, _ := probe(t, mux, "/readyz"); code != http.StatusOK {
		t.Fatalf("inside the cache window the old answer stands, got %d", code)
	}
	if calls.Load() != 1 {
		t.Fatalf("checks = %d, want 1 (cached)", calls.Load())
	}
	time.Sleep(2 * testTTL)
	wantDownWithoutErrorText(t, mux)
	if code, _ := probe(t, mux, "/livez"); code != http.StatusOK {
		t.Fatal("liveness must not follow a dependency")
	}
	down.Store(false)
	time.Sleep(2 * testTTL)
	if code, r := probe(t, mux, "/readyz"); code != http.StatusOK || r.Status != health.StateOK {
		t.Fatalf("recovered: %d %+v", code, r)
	}
}

// wantDownWithoutErrorText checks /readyz is 503 with the gateway down, its
// error reduced to a class.
func wantDownWithoutErrorText(t *testing.T, mux http.Handler) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var r readyBody
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if rec.Code != http.StatusServiceUnavailable || r.Status != health.StateDown || r.Dependencies[0].State != health.StateDown || r.Dependencies[0].Error != "error" {
		t.Fatalf("down: %d %+v", rec.Code, r)
	}
	if body := rec.Body.String(); strings.Contains(body, "SHOULD-NOT-LEAK") || strings.Contains(body, "example.test") {
		t.Fatalf("error text reached the body: %s", body)
	}
}

func TestHealth_OptionalDependencyDegrades(t *testing.T) {
	c := health.New()
	if err := c.Register(
		health.Dependency{Name: "gateway", Required: true, Check: func(context.Context) error { return nil }},
		health.Dependency{Name: "hydra-jwks", Check: func(context.Context) error { return &statusError{code: 500} }},
	); err != nil {
		t.Fatal(err)
	}
	code, r := probe(t, healthMux(t, c), "/readyz")
	if code != http.StatusOK || r.Status != health.StateDegraded || r.Dependencies[1].State != health.StateDegraded {
		t.Fatalf("got %d %+v", code, r)
	}
}

func TestHealth_CheckTimesOut(t *testing.T) {
	c := health.New(health.WithTimeout(20 * time.Millisecond))
	if err := c.Register(health.Dependency{Name: "gateway", Required: true, Check: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	if r := c.Report(t.Context()); r.Dependencies[0].Error != "timeout" {
		t.Fatalf("got %+v", r)
	}
}

func TestHealth_HTTPCheckAgainstAStoppedServer(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	check := checkHTTP(srv.Client(), srv.URL+"/readyz")
	class := func() string {
		c := health.New()
		if err := c.Register(health.Dependency{Name: "gateway", Check: check}); err != nil {
			t.Fatal(err)
		}
		return c.Report(t.Context()).Dependencies[0].Error
	}
	if err := check(context.Background()); err != nil {
		t.Fatalf("up: %v", err)
	}
	status.Store(http.StatusUnauthorized)
	if got := class(); got != "unauthenticated" {
		t.Fatalf("401 class = %q", got)
	}
	status.Store(http.StatusInternalServerError)
	if got := class(); got != "error" {
		t.Fatalf("500 class = %q", got)
	}
	srv.Close()
	if got := class(); got != "refused" {
		t.Fatalf("stopped server class = %q, want refused", got)
	}
}

// TestHealth_HeaderNames pins the exact header names /readyz and /livez
// carry; the gateway's diagnostics read the build from them.
func TestHealth_HeaderNames(t *testing.T) {
	stampBuild(t)
	f := newFakeDeps(t)
	mux := healthMux(t, testChecker(t, config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true}))
	keys := func(path string) (http.Header, []string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var out []string
		for k := range rec.Header() {
			if strings.HasPrefix(k, "Sneakers-") {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return rec.Header(), out
	}
	h, got := keys("/readyz")
	if want := []string{"Sneakers-Commit", "Sneakers-Depstate-Gateway", "Sneakers-Version"}; !slices.Equal(got, want) {
		t.Fatalf("/readyz headers = %v, want %v", got, want)
	}
	if h.Get("Sneakers-Version") != "v9.9.9-test" || h.Get("Sneakers-Commit") != "0123456789abcdef" {
		t.Fatalf("/readyz build headers = %v", h)
	}
	if _, got := keys("/livez"); !slices.Equal(got, []string{"Sneakers-Commit", "Sneakers-Version"}) {
		t.Fatalf("/livez headers = %v", got)
	}
}
