// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSw(static []string, f DisabledFetcher, c *clock) *Switches {
	s := NewSwitches(static, f, time.Minute, zerolog.Nop())
	s.now = c.now
	return s
}

func TestSwitchesWithoutFetcherUseStaticList(t *testing.T) {
	s := newSw([]string{"sneakers_rotate_secret"}, nil, &clock{time.Unix(0, 0)})
	off := s.Off(context.Background(), "tok")
	if !off["sneakers_rotate_secret"] || len(off) != 1 {
		t.Fatalf("off = %v", off)
	}
}

func TestSwitchesFetchOnceWithinTTLThenAgain(t *testing.T) {
	var calls atomic.Int32
	list := []string{"sneakers_find_secrets"}
	c := &clock{time.Unix(0, 0)}
	s := newSw(nil, func(_ context.Context, tok string) ([]string, error) {
		calls.Add(1)
		if tok != "tok" {
			t.Errorf("fetch got token %q, want the caller's", tok)
		}
		return list, nil
	}, c)
	for i := 0; i < 3; i++ {
		if !s.Off(context.Background(), "tok")["sneakers_find_secrets"] {
			t.Fatal("fetched switch not applied")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("fetched %d times within the TTL, want 1", calls.Load())
	}
	list = []string{"sneakers_rotate_secret"}
	c.t = c.t.Add(2 * time.Minute)
	off := s.Off(context.Background(), "tok")
	if calls.Load() != 2 || !off["sneakers_rotate_secret"] || off["sneakers_find_secrets"] {
		t.Fatalf("after TTL: calls=%d off=%v", calls.Load(), off)
	}
}

func TestSwitchesFallBackToStaticWhenGatewayDown(t *testing.T) {
	s := newSw([]string{"sneakers_rotate_secret"}, func(context.Context, string) ([]string, error) {
		return nil, errors.New("gateway down")
	}, &clock{time.Unix(0, 0)})
	if !s.Off(context.Background(), "tok")["sneakers_rotate_secret"] {
		t.Fatal("static list not used while the gateway is unreachable")
	}
}

func TestSwitchesKeepLastGoodWhenGatewayFailsLater(t *testing.T) {
	fail := false
	c := &clock{time.Unix(0, 0)}
	s := newSw([]string{"sneakers_rotate_secret"}, func(context.Context, string) ([]string, error) {
		if fail {
			return nil, errors.New("down")
		}
		return []string{"sneakers_find_secrets"}, nil
	}, c)
	_ = s.Off(context.Background(), "tok")
	fail = true
	c.t = c.t.Add(2 * time.Minute)
	off := s.Off(context.Background(), "tok")
	if !off["sneakers_find_secrets"] || off["sneakers_rotate_secret"] {
		t.Fatalf("want the last good fetched list, got %v", off)
	}
}

func TestSwitchesBackOffAfterFailure(t *testing.T) {
	var calls atomic.Int32
	c := &clock{time.Unix(0, 0)}
	s := newSw(nil, func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("down")
	}, c)
	for i := 0; i < 5; i++ {
		_ = s.Off(context.Background(), "tok")
	}
	if calls.Load() != 1 {
		t.Fatalf("hammered a failing gateway: %d calls", calls.Load())
	}
	c.t = c.t.Add(10 * time.Second)
	_ = s.Off(context.Background(), "tok")
	if calls.Load() != 2 {
		t.Fatalf("no retry after the back-off: %d calls", calls.Load())
	}
}

func TestSwitchesIgnoreUnknownNamesFromGateway(t *testing.T) {
	s := newSw(nil, func(context.Context, string) ([]string, error) {
		return []string{"sneakers_find_secrets", "sneakers_from_a_newer_gateway"}, nil
	}, &clock{time.Unix(0, 0)})
	off := s.Off(context.Background(), "tok")
	if !off["sneakers_find_secrets"] || off["sneakers_from_a_newer_gateway"] {
		t.Fatalf("off = %v", off)
	}
}

func TestSwitchesWithoutTokenUseCacheOrStatic(t *testing.T) {
	var calls atomic.Int32
	s := newSw([]string{"sneakers_rotate_secret"}, func(context.Context, string) ([]string, error) {
		calls.Add(1)
		return nil, nil
	}, &clock{time.Unix(0, 0)})
	if !s.Off(context.Background(), "")["sneakers_rotate_secret"] || calls.Load() != 0 {
		t.Fatal("a call with no token must not fetch and must use the static list")
	}
}

// A switch the gateway turns on after start-up takes effect on the next
// refresh without a restart, through the real server middleware.
func TestRestrictWithAppliesGatewaySettingLive(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"disabledMcpTools":["sneakers_find_secrets"]}}`)
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Register(s, gwclient.New(gw.URL, nil), zerolog.Nop())
	sw := NewSwitches(nil, gwclient.New(gw.URL, nil).DisabledMcpTools, time.Minute, zerolog.Nop())
	RestrictWith(s, sw, zerolog.Nop())
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	// The in-memory session carries no verified bearer, so no fetch can run:
	// the floor (empty) applies and nothing is hidden.
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != len(Names()) {
		t.Fatalf("listed %d tools without a bearer, want all %d", len(res.Tools), len(Names()))
	}
	// With a bearer, the fetched list applies.
	off := sw.Off(ctx, "tok")
	if !off["sneakers_find_secrets"] {
		t.Fatalf("fetched switch not applied: %v", off)
	}
	if got := toolRefusal("sneakers_find_secrets"); !strings.Contains(got, "Disabled MCP tools") {
		t.Fatalf("refusal %q does not name the setting", got)
	}
}
