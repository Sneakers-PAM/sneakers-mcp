// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestUserTokenIsAcceptedAndVerifiedByTheGateway(t *testing.T) {
	h := newHarnessWith(t, apiOnly)
	tok := "snk_u_" + saToken(t)
	h.allow(tok)

	resp := rawPost(t, h.srv.URL+"/mcp", "Bearer "+tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user token: status = %d, want 200", resp.StatusCode)
	}
	h.revoke(tok)
	expect401(t, rawPost(t, h.srv.URL+"/mcp", "Bearer snk_u_"+saToken(t)))
}

func TestMetadataAdvertisesTheSneakersAuthorizationServer(t *testing.T) {
	h := newHarnessWith(t, func(c *config) { apiOnly(c); c.AuthorizationServer = "https://sneakers.example.org" })
	resp, err := http.Get(h.srv.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var md struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&md)
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://sneakers.example.org" {
		t.Fatalf("authorization_servers = %v", md.AuthorizationServers)
	}
}
