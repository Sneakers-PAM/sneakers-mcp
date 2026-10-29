// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

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
	// another state; token is what /oauth2/token hands out.
	deny, wrongState bool
	token            string
	exchanged        int
}

func newGateway(t *testing.T) *gateway {
	g := &gateway{t: t, token: "snk_u_" + strings.Repeat("A", 43)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", g.metadata)
	mux.HandleFunc("POST /oauth2/register", g.register)
	mux.HandleFunc("GET /oauth2/authorize", g.authorize)
	mux.HandleFunc("POST /oauth2/token", g.exchange)
	g.srv = httptest.NewServer(mux)
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
		f.Get("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"access_token": g.token, "token_type": "Bearer"})
}

// browser follows the authorize URL the way a browser would, redirects
// included, so the loopback listener gets the callback.
func browser(t *testing.T, opened *string) func(string) {
	return func(u string) {
		*opened = u
		go func() {
			resp, err := http.Get(u) // #nosec G107 -- the test's own authorize URL
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
		Base: g.srv.URL, ClientName: "sneakers-put on laptop-01", Open: browser(t, opened), Out: &out, HTTP: g.srv.Client(),
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
}

func TestLoginRefusesWhatTheFlowDoesntProve(t *testing.T) {
	for name, set := range map[string]func(*gateway){
		"denied":            func(g *gateway) { g.deny = true },
		"another state":     func(g *gateway) { g.wrongState = true },
		"a service token":   func(g *gateway) { g.token = "snk_sa_" + strings.Repeat("A", 43) },
		"a malformed token": func(g *gateway) { g.token = "snk_u_short value" },
	} {
		t.Run(name, func(t *testing.T) {
			g := newGateway(t)
			set(g)
			var opened string
			if token, err := login(t, g, &opened); err == nil {
				t.Fatalf("logged in with %q", token)
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
	if g.exchanged != 0 {
		t.Fatalf("exchanged %d codes", g.exchanged)
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
	var opened string
	browser(t, &opened)(link)
	if err := <-done; err != nil {
		t.Fatal(err)
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
