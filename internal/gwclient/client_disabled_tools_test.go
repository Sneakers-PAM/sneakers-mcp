// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestDisabledMcpToolsDecodesNames(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"disabledMcpTools":["sneakers_rotate_secret","sneakers_find_secrets"]}}`, 200)
	got, err := New(srv.URL, nil).DisabledMcpTools(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"sneakers_rotate_secret", "sneakers_find_secrets"}) {
		t.Fatalf("got %v", got)
	}
	if !strings.Contains(cp.query, "disabledMcpTools") {
		t.Fatalf("query = %q", cp.query)
	}
}

func TestDisabledMcpToolsEmptyListIsAllOn(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"disabledMcpTools":[]}}`, 200)
	got, err := New(srv.URL, nil).DisabledMcpTools(context.Background(), "t")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %v, %v; want an empty non-nil list", got, err)
	}
}

func TestDisabledMcpToolsRefusedWithoutTokenOrOnError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"errors":[{"message":"nope"}]}`, 200)
	if _, err := New(srv.URL, nil).DisabledMcpTools(context.Background(), ""); err != ErrNoToken {
		t.Fatalf("no token: %v", err)
	}
	if _, err := New(srv.URL, nil).DisabledMcpTools(context.Background(), "t"); err == nil {
		t.Fatal("a GraphQL error must be returned, not read as 'all on'")
	}
}
