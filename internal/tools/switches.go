// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
)

const (
	// failureBackoff is how long a failed fetch is not retried, so a down
	// gateway is not hit on every call.
	failureBackoff = 5 * time.Second
	// fetchTimeout bounds one fetch; a slow gateway never holds a tool call.
	fetchTimeout = 3 * time.Second
)

// DisabledFetcher returns the tool names the gateway's MCP setting turns off.
// token is a verified caller's bearer; the setting is install-wide, so any
// caller's token will do.
type DisabledFetcher func(ctx context.Context, token string) ([]string, error)

// Switches decides which tools are off. The list from MCP_DISABLED_TOOLS is
// the floor: used alone when there is no fetcher, and while the gateway has
// not yet answered or is unreachable. A fetched list replaces it, is cached
// for the TTL, and stays in use if a later fetch fails. It is safe for
// concurrent use.
type Switches struct {
	static map[string]bool
	fetch  DisabledFetcher
	ttl    time.Duration
	log    zerolog.Logger
	known  []string
	now    func() time.Time // test hook

	mu      sync.Mutex
	current map[string]bool
	until   time.Time // no fetch before this
	fetched bool      // current came from the gateway
}

// NewSwitches builds Switches from the static list, an optional fetcher and
// the cache TTL.
func NewSwitches(static []string, fetch DisabledFetcher, ttl time.Duration, log zerolog.Logger) *Switches {
	s := &Switches{static: toSet(static, nil), fetch: fetch, ttl: ttl, log: log, now: time.Now}
	if fetch != nil {
		s.known = Names()
	}
	return s
}

func toSet(names, only []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		if only == nil || slices.Contains(only, n) {
			m[n] = true
		}
	}
	return m
}

// Off returns the set of tool names that are off for a call carrying token.
func (s *Switches) Off(ctx context.Context, token string) map[string]bool {
	if s.fetch == nil {
		return s.static
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "" && !s.now().Before(s.until) {
		s.refresh(ctx, token)
	}
	if s.fetched {
		return s.current
	}
	return s.static
}

// refresh fetches once. The caller holds s.mu.
func (s *Switches) refresh(ctx context.Context, token string) {
	fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	names, err := s.fetch(fctx, token)
	if err != nil {
		s.until = s.now().Add(failureBackoff)
		s.log.Warn().Err(err).Bool("using_last_good", s.fetched).Msg("mcp disabled-tools fetch failed")
		return
	}
	set := toSet(names, s.known)
	if len(set) != len(names) {
		s.log.Warn().Int("listed", len(names)).Int("known", len(set)).Msg("mcp disabled-tools: ignoring names this server does not have")
	}
	s.current, s.fetched, s.until = set, true, s.now().Add(s.ttl)
	s.log.Debug().Int("off", len(set)).Msg("mcp disabled-tools fetched")
}

// bearerOf returns the verified caller's bearer from a server request, or "".
func bearerOf(req mcp.Request) string {
	if req == nil {
		return ""
	}
	ex := req.GetExtra()
	if ex == nil || ex.TokenInfo == nil || ex.Header == nil {
		return ""
	}
	f := strings.Fields(ex.Header.Get("Authorization"))
	if len(f) != 2 || !strings.EqualFold(f[0], "bearer") {
		return ""
	}
	return f[1]
}
