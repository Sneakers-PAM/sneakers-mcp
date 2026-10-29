// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LoginOptions shape one sign-in.
type LoginOptions struct {
	// Base is the Sneakers base URL, already checked (Base).
	Base string
	// ClientName is what the consent page shows the person, such as
	// "sneakers-put on laptop-01".
	ClientName string
	// Open shows the sign-in page in a browser; nil only prints its link.
	Open func(url string)
	// Out is where the link and the progress go.
	Out io.Writer
	// HTTP calls the gateway; nil means a client with a 30-second timeout.
	HTTP *http.Client
}

// callbackPath is the loopback redirect URI's path. The gateway takes any
// port on it, so each sign-in listens on a fresh one.
const callbackPath = "/callback"

// Login signs the person in through the gateway's OAuth server for native
// clients, the one an MCP client uses (RFC 8252): it registers a client
// with a loopback redirect URI, sends the person to the sign-in and consent
// in their browser with a PKCE S256 challenge, takes the code on
// 127.0.0.1, and exchanges it for a personal token. Nobody copies a token.
func Login(ctx context.Context, o LoginOptions) (string, error) {
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	meta, err := discover(ctx, hc, o.Base)
	if err != nil {
		return "", err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("login: listen on 127.0.0.1: %w", err)
	}
	defer func() { _ = ln.Close() }()
	redirect := fmt.Sprintf("http://%s%s", ln.Addr().String(), callbackPath)
	clientID, err := register(ctx, hc, meta.Registration, o.ClientName)
	if err != nil {
		return "", err
	}
	verifier, err := random()
	if err != nil {
		return "", err
	}
	state, err := random()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	link := meta.Authorization + "?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {state},
	}.Encode()
	_, _ = fmt.Fprintf(o.Out, "Sign in to Sneakers and approve %q in your browser.\nIf no browser opened, open this link:\n\n  %s\n\n", o.ClientName, link)
	if o.Open != nil {
		o.Open(link)
	}
	code, err := callback(ctx, ln, state)
	if err != nil {
		return "", err
	}
	token, err := exchange(ctx, hc, meta.Token, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier},
	})
	if err != nil {
		return "", err
	}
	if !personalToken.MatchString(token) {
		return "", errors.New("login: the gateway's answer isn't a personal token")
	}
	return token, nil
}

type metadata struct {
	Authorization string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Registration  string   `json:"registration_endpoint"`
	Methods       []string `json:"code_challenge_methods_supported"`
}

// discover reads the authorization server metadata, and refuses endpoints
// on another origin: the code and the token go only to the gateway named
// in SNEAKERS_URL.
func discover(ctx context.Context, hc *http.Client, base string) (metadata, error) {
	var m metadata
	if err := getJSON(ctx, hc, base+"/.well-known/oauth-authorization-server", &m); err != nil {
		return metadata{}, fmt.Errorf("login: this gateway has no sign-in for native clients (OAUTH_PUBLIC_URL): %w", err)
	}
	s256 := false
	for _, x := range m.Methods {
		s256 = s256 || x == "S256"
	}
	if !s256 {
		return metadata{}, errors.New("login: the gateway doesn't offer PKCE S256")
	}
	b, _ := url.Parse(base)
	for _, e := range []string{m.Authorization, m.Token, m.Registration} {
		u, err := url.Parse(e)
		if err != nil || u.Scheme != b.Scheme || !strings.EqualFold(u.Host, b.Host) {
			return metadata{}, fmt.Errorf("login: the gateway's metadata names %q, not an endpoint on %s", e, base)
		}
	}
	return m, nil
}

func register(ctx context.Context, hc *http.Client, endpoint, name string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name": name, "redirect_uris": []string{"http://127.0.0.1" + callbackPath},
		"grant_types": []string{"authorization_code"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := doJSON(hc, req, &out); err != nil {
		return "", fmt.Errorf("login: register the client: %w", err)
	}
	if out.ClientID == "" {
		return "", errors.New("login: the gateway registered no client id")
	}
	return out.ClientID, nil
}

// callback waits for the browser's redirect to the loopback listener and
// returns the code once its state is this sign-in's. A callback with
// another state, or an error, ends the sign-in without an exchange.
func callback(ctx context.Context, ln net.Listener, state string) (string, error) {
	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res result
		switch {
		case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1:
			res.err = errors.New("login: the sign-in came back with another state; start again")
		case q.Get("error") != "":
			res.err = fmt.Errorf("login: the sign-in wasn't approved (%s)", q.Get("error"))
		case q.Get("code") == "":
			res.err = errors.New("login: the sign-in came back without a code")
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "Sneakers sign-in failed. Go back to the terminal for the reason.\n")
		} else {
			_, _ = io.WriteString(w, "Signed in to Sneakers. You can close this tab and go back to the terminal.\n")
		}
		select {
		case got <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	select {
	case res := <-got:
		return res.code, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("login: no sign-in came back: %w", ctx.Err())
	}
}

func exchange(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(hc, req, &out); err != nil {
		return "", fmt.Errorf("login: exchange the code: %w", err)
	}
	return out.AccessToken, nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return doJSON(hc, req, out)
}

// doJSON sends req and decodes a 2xx JSON answer. An error answer is
// reported by its OAuth error code only: its body never reaches the output.
func doJSON(hc *http.Client, req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req) // #nosec G704 -- the gateway SNEAKERS_URL names, checked by discover
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (%s)", resp.Status, e.Error)
		}
		return errors.New(resp.Status)
	}
	return json.Unmarshal(body, out)
}

func random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
