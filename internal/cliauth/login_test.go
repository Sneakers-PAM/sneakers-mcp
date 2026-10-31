// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	certkit "github.com/Bugs5382/go-certkit"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
)

// gateway is the gateway's OAuth server for native clients, as its
// internal/bff/oauth.go answers: loopback redirect URIs only, PKCE S256,
// and the code exchanged for a personal token. Its authorize step stands in
// for the user signing in and approving at once.
type gateway struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	registered []string
	clientName string
	challenge  string
	redirect   string
	state      string
	// deny answers the authorize step with access_denied; wrongState with
	// another state; token is what /oauth2/token hands out, and with none it refuses the code.
	deny, wrongState bool
	token            string
	exchanged        int
	// landed gets the query the browser ends on, the Sneakers page that
	// says how the sign-in went, and how many codes were exchanged by then.
	landed chan landing
}

type landing struct {
	query     url.Values
	exchanged int
}

func newGateway(t *testing.T) *gateway {
	return startGateway(t, (*httptest.Server).Start)
}

// newTLSGateway is the gateway on localhost over HTTPS with box's
// certificate, as a new appliance serves it.
func newTLSGateway(t *testing.T, box certkit.Bundle) *gateway {
	return startGateway(t, func(srv *httptest.Server) { startBox(t, srv, box) })
}

func startGateway(t *testing.T, start func(*httptest.Server)) *gateway {
	g := &gateway{t: t, token: "snk_u_" + strings.Repeat("A", 43), landed: make(chan landing, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", g.metadata)
	mux.HandleFunc("POST /oauth2/register", g.register)
	mux.HandleFunc("GET /oauth2/authorize", g.authorize)
	mux.HandleFunc("POST /oauth2/token", g.exchange)
	mux.HandleFunc("GET /cli/signed-in", g.land)
	g.srv = httptest.NewUnstartedServer(mux)
	start(g.srv)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gateway) metadata(w http.ResponseWriter, _ *http.Request) {
	base := g.srv.URL
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer": base, "authorization_endpoint": base + "/oauth2/authorize", "token_endpoint": base + "/oauth2/token",
		"registration_endpoint": base + "/oauth2/register", "code_challenge_methods_supported": []string{"S256"},
	})
}

func (g *gateway) register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	for _, u := range body.RedirectURIs {
		if p, err := url.Parse(u); err != nil || p.Scheme != "http" || p.Hostname() != "127.0.0.1" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_redirect_uri"})
			return
		}
	}
	g.mu.Lock()
	g.registered, g.clientName = body.RedirectURIs, body.ClientName
	g.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "client-1", "redirect_uris": body.RedirectURIs})
}

func (g *gateway) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	g.mu.Lock()
	defer g.mu.Unlock()
	if q.Get("client_id") != "client-1" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorize request: "+r.URL.RawQuery, http.StatusBadRequest)
		return
	}
	g.challenge, g.redirect, g.state = q.Get("code_challenge"), q.Get("redirect_uri"), q.Get("state")
	params := url.Values{"code": {"code-1"}, "state": {g.state}}
	switch {
	case g.deny:
		params = url.Values{"error": {"access_denied"}, "state": {g.state}}
	case g.wrongState:
		params.Set("state", "not-the-state")
	}
	http.Redirect(w, r, g.redirect+"?"+params.Encode(), http.StatusFound)
}

func (g *gateway) exchange(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	g.mu.Lock()
	defer g.mu.Unlock()
	g.exchanged++
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code-1" || f.Get("client_id") != "client-1" ||
		f.Get("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || g.token == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": g.token, "token_type": "Bearer"})
}

func (g *gateway) land(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	l := landing{query: r.URL.Query(), exchanged: g.exchanged}
	g.mu.Unlock()
	select {
	case g.landed <- l:
	default:
		g.t.Errorf("the browser landed twice: %v", l.query)
	}
	_, _ = io.WriteString(w, "<!doctype html><title>Sneakers-PAM</title>")
}

// landedOn waits for the browser to reach the Sneakers page.
func (g *gateway) landedOn(t *testing.T) landing {
	t.Helper()
	select {
	case l := <-g.landed:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("the browser never reached the Sneakers page")
		return landing{}
	}
}

// browser follows the authorize URL the way a browser would, redirects
// included, so the loopback listener gets the callback.
func browser(t *testing.T, opened *string) func(string) {
	return browserWith(t, http.DefaultClient, opened)
}

// browserWith is browser with hc, such as one that trusts a box's own
// certificate the way a person's browser does once they accept it.
func browserWith(t *testing.T, hc *http.Client, opened *string) func(string) {
	return func(u string) {
		*opened = u
		go func() {
			resp, err := hc.Get(u) // #nosec G107 -- the test's own authorize URL
			if err != nil {
				t.Errorf("the browser couldn't follow %s: %v", u, err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
}

func login(t *testing.T, g *gateway, opened *string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out strings.Builder
	return cliauth.Login(ctx, cliauth.LoginOptions{
		Base: g.srv.URL, ClientName: "sneakers-put on laptop-01", Command: "sneakers-put", Open: browser(t, opened), Out: &out, HTTP: g.srv.Client(),
	})
}

func TestLoginGetsAPersonalTokenThroughLoopbackAndPKCE(t *testing.T) {
	g := newGateway(t)
	var opened string
	token, err := login(t, g, &opened)
	if err != nil {
		t.Fatal(err)
	}
	if token != g.token {
		t.Fatalf("token %q", token)
	}
	if len(g.registered) != 1 || g.registered[0] != "http://127.0.0.1/callback" || g.clientName != "sneakers-put on laptop-01" {
		t.Fatalf("registered %v as %q", g.registered, g.clientName)
	}
	// The redirect carries the port the listener got, which the gateway
	// matches without the port; the exchange repeats it exactly.
	if u, _ := url.Parse(g.redirect); u.Port() == "" || u.Path != "/callback" {
		t.Fatalf("redirect %q", g.redirect)
	}
	if !strings.HasPrefix(opened, g.srv.URL+"/oauth2/authorize?") || len(g.state) < 32 {
		t.Fatalf("opened %q with state %q", opened, g.state)
	}
	// The browser ends on the Sneakers page, sent there only once the token
	// is in hand, never on a page the loopback listener serves.
	if l := g.landedOn(t); l.exchanged != 1 || l.query.Encode() != "client=sneakers-put" {
		t.Fatalf("landed on %q after %d exchanges", l.query.Encode(), l.exchanged)
	}
}

func TestLoginRefusesWhatTheFlowDoesntProve(t *testing.T) {
	for name, c := range map[string]struct {
		set    func(*gateway)
		reason string
	}{
		"denied":            {func(g *gateway) { g.deny = true }, "denied"},
		"another state":     {func(g *gateway) { g.wrongState = true }, "state"},
		"a refused code":    {func(g *gateway) { g.token = "" }, "exchange"},
		"a service token":   {func(g *gateway) { g.token = "snk_sa_" + strings.Repeat("A", 43) }, "exchange"},
		"a malformed token": {func(g *gateway) { g.token = "snk_u_short value" }, "exchange"},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t)
			c.set(g)
			var opened string
			if token, err := login(t, g, &opened); err == nil {
				t.Fatalf("logged in with %q", token)
			}
			if l := g.landedOn(t); l.query.Get("client") != "sneakers-put" || l.query.Get("reason") != c.reason {
				t.Fatalf("landed on %q, want reason %s", l.query.Encode(), c.reason)
			}
		})
	}
}

// The exchange never runs for a callback that doesn't carry this login's
// state: a page that redirects a browser to the loopback port can't feed it
// a code.
func TestLoginDoesntExchangeAForeignCallback(t *testing.T) {
	g := newGateway(t)
	g.wrongState = true
	var opened string
	if _, err := login(t, g, &opened); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("got %v", err)
	}
	if l := g.landedOn(t); l.exchanged != 0 {
		t.Fatalf("exchanged %d codes", l.exchanged)
	}
}

func TestLoginGivesUpWhenTheContextEnds(t *testing.T) {
	g := newGateway(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := cliauth.Login(ctx, cliauth.LoginOptions{Base: g.srv.URL, ClientName: "x", Open: func(string) {}, Out: &strings.Builder{}, HTTP: g.srv.Client()})
	if err == nil {
		t.Fatal("a login nobody finished returned no error")
	}
}

// With no way to open a browser, the link is printed for the person to open.
func TestLoginPrintsTheLinkWithoutABrowser(t *testing.T) {
	g := newGateway(t)
	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := cliauth.Login(ctx, cliauth.LoginOptions{Base: g.srv.URL, ClientName: "x", Out: &syncWriter{w: &out}, HTTP: g.srv.Client()})
		done <- err
	}()
	var link string
	for link == "" {
		select {
		case err := <-done:
			t.Fatalf("login ended first: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		for _, l := range strings.Fields(readSync(&out)) {
			if strings.HasPrefix(l, g.srv.URL+"/oauth2/authorize?") {
				link = l
			}
		}
	}
	// With no browser here, it says how to finish from another machine:
	// forward the loopback port the redirect names.
	u, _ := url.Parse(link)
	redirect, _ := url.Parse(u.Query().Get("redirect_uri"))
	if want := "ssh -L " + redirect.Port() + ":127.0.0.1:" + redirect.Port(); !strings.Contains(readSync(&out), want) {
		t.Fatalf("no %q in %q", want, readSync(&out))
	}
	var opened string
	browser(t, &opened)(link)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if l := g.landedOn(t); l.exchanged != 1 {
		t.Fatalf("landed after %d exchanges", l.exchanged)
	}
}

var outMu sync.Mutex

type syncWriter struct{ w *strings.Builder }

func (s *syncWriter) Write(p []byte) (int, error) {
	outMu.Lock()
	defer outMu.Unlock()
	return s.w.Write(p)
}

func readSync(b *strings.Builder) string {
	outMu.Lock()
	defer outMu.Unlock()
	return b.String()
}
