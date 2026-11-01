// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"strings"
	"testing"
)

func TestListExtensionPacksDecodesFields(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"availableExtensions":[{"id":"ext-example","name":"Example Cloud","fields":[{"key":"apiKey","label":"API key","kind":"PASSWORD","required":true,"sensitive":true}]}]}}`, 200)

	out, err := New(srv.URL, nil).ListExtensionPacks(context.Background(), "t")
	if err != nil {
		t.Fatalf("ListExtensionPacks: %v", err)
	}
	if len(out) != 1 || out[0].ID != "ext-example" || !out[0].Fields[0].Sensitive {
		t.Fatalf("decoded = %+v", out)
	}
	if cp.auth != "Bearer t" {
		t.Fatalf("Authorization = %q", cp.auth)
	}
}

func TestListExtensionPacksEmptyIsNotNil(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"availableExtensions":[]}}`, 200)
	if out, err := New(srv.URL, nil).ListExtensionPacks(context.Background(), "t"); err != nil || out == nil {
		t.Fatalf("out = %v, err = %v", out, err)
	}
}

func TestImportExtensionPackSendsTheIDAndDecodesTheType(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"importExtension":{"id":"ext-example","name":"Example Cloud","fields":[]}}}`, 200)

	ty, err := New(srv.URL, nil).ImportExtensionPack(context.Background(), "tok", "ext-example")
	if err != nil || ty.ID != "ext-example" || ty.Name != "Example Cloud" {
		t.Fatalf("ty=%+v err=%v", ty, err)
	}
	if !strings.Contains(cp.query, "importExtension") || cp.vars["id"] != "ext-example" {
		t.Fatalf("query=%q vars=%#v", cp.query, cp.vars)
	}
}

func TestImportExtensionPackWithNoTypeIsAnError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"importExtension":null}}`, 200)
	if _, err := New(srv.URL, nil).ImportExtensionPack(context.Background(), "tok", "ext-example"); err == nil {
		t.Fatal("want an error")
	}
}
