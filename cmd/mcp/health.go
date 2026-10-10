// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/Bugs5382/go-buildinfo/httpbuildinfo"
	log "github.com/Bugs5382/go-log"
)

// headerPrefix starts the build and dependency headers /readyz and /livez
// carry: Sneakers-Version, Sneakers-Commit, Sneakers-Depstate-<name>.
const headerPrefix = "sneakers"

// cacheTTL is how long a check's result is reused; checkTimeout bounds each
// check.
const (
	cacheTTL     = 5 * time.Second
	checkTimeout = time.Second
)

// newHealthChecker lists the MCP server's readiness dependencies. The gateway
// is required: every tool call is a machine GraphQL call to it, so without it
// the server can't do anything. It's checked at the gateway's own /readyz,
// never with a token. Hydra's JWKS verifies the Hydra bearer: required when
// that is the only bearer mode, optional (degraded) when API tokens still work.
// opts follow the defaults, so a test can shorten the TTL. /readyz only reads
// the checker's cache: buildHandler runs the checks in the background once per
// cacheTTL, so a slow gateway /readyz never makes this probe wait.
func newHealthChecker(cfg config, lg log.Logger, opts ...health.Option) (*health.Checker, error) {
	httpc := &http.Client{Timeout: checkTimeout}
	deps := []health.Dependency{{Name: "gateway", Required: true, Check: checkHTTP(httpc, originOf(cfg.GatewayURL)+"/readyz")}}
	if cfg.hydraEnabled() {
		deps = append(deps, health.Dependency{Name: "hydra-jwks", Required: !cfg.AcceptAPITokens, Check: checkHTTP(httpc, cfg.HydraJWKSURL)})
	}
	c := health.New(append([]health.Option{health.WithBackgroundRefresh(), health.WithTTL(cacheTTL), health.WithTimeout(checkTimeout), health.WithLogger(lg)}, opts...)...)
	return c, c.Register(deps...)
}

// statusError is an HTTP check's non-success answer.
type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("status %d", e.code) }

// checkHTTP checks that a GET of url answers 2xx. Its errors carry the classes
// the other Sneakers-PAM services report: refused, unauthenticated (401 or
// 403) and unavailable for other network errors; go-buildinfo classes the
// rest (timeout, error).
func checkHTTP(client *http.Client, url string) func(context.Context) error {
	return func(ctx context.Context) error {
		err := getOK(ctx, client, url)
		var se *statusError
		var ne net.Error
		switch {
		case err == nil, errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, syscall.ECONNREFUSED):
			return health.Classify(err, "refused")
		case errors.As(err, &se):
			if se.code == http.StatusUnauthorized || se.code == http.StatusForbidden {
				return health.Classify(err, "unauthenticated")
			}
			return err
		case errors.As(err, &ne) && !ne.Timeout():
			return health.Classify(err, "unavailable")
		}
		return err
	}
}

func getOK(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &statusError{code: resp.StatusCode}
	}
	return nil
}

// originOf is the scheme and host of a URL.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// mountHealth serves go-buildinfo's /livez (the process only) and /readyz
// (the dependencies), outside auth. Both carry the build headers the
// gateway's diagnostics read.
func mountHealth(mux *http.ServeMux, c *health.Checker) error {
	h, err := httpbuildinfo.New(httpbuildinfo.WithPrefix(headerPrefix), httpbuildinfo.WithChecker(c))
	if err != nil {
		return err
	}
	mux.Handle("GET /livez", h.Livez())
	mux.Handle("GET /readyz", h.Readyz())
	return nil
}

// isProbe is a kubelet path, left out of the request log.
func isProbe(path string) bool {
	return path == "/livez" || path == "/readyz"
}
