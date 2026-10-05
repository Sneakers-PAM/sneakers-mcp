// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/url"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/health"
	"github.com/rs/zerolog"
)

// newHealthChecker lists the MCP server's readiness dependencies. The gateway
// is required: every tool call is a machine GraphQL call to it, so without it
// the server can't do anything. It's checked at the gateway's own /readyz,
// never with a token. Hydra's JWKS verifies the Hydra bearer: required when
// that is the only bearer mode, optional (degraded) when API tokens still work.
func newHealthChecker(cfg config, logger zerolog.Logger) *health.Checker {
	httpc := &http.Client{Timeout: health.DefaultTimeout}
	deps := []health.Dep{{Name: "gateway", Required: true, Check: health.HTTP(httpc, originOf(cfg.GatewayURL)+"/readyz")}}
	if cfg.hydraEnabled() {
		deps = append(deps, health.Dep{Name: "hydra-jwks", Required: !cfg.AcceptAPITokens, Check: health.HTTP(httpc, cfg.HydraJWKSURL)})
	}
	return &health.Checker{Deps: deps, Log: &logger}
}

// originOf is the scheme and host of a URL.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// mountHealth serves /livez (the process only) and /readyz (the
// dependencies), outside auth like /health.
func mountHealth(mux *http.ServeMux, c *health.Checker) {
	mux.Handle("GET /livez", c.Livez())
	mux.Handle("GET /readyz", c.Readyz())
}

// isProbe is a kubelet path, left out of the request log.
func isProbe(path string) bool {
	return path == "/health" || path == "/livez" || path == "/readyz"
}
