// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestListExtensionPacksMapsFields(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"availableExtensions":[{"id":"ext-example","name":"Example Cloud","fields":[`+
		`{"key":"apiKey","label":"API key","kind":"PASSWORD","required":true,"sensitive":true}]}]}}`)

	_, out, err := newTools(gw.URL, nil).listExtensionPacks(context.Background(), callReq("Bearer t"), listExtensionPacksIn{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if len(out.Packs) != 1 || out.Packs[0].ID != "ext-example" || !out.Packs[0].Fields[0].Sensitive {
		t.Fatalf("Packs = %+v", out.Packs)
	}
}

func TestListExtensionPacksEmptyIsAnEmptyList(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"availableExtensions":[]}}`)
	_, out, err := newTools(gw.URL, nil).listExtensionPacks(context.Background(), callReq("Bearer t"), listExtensionPacksIn{})
	if err != nil || out.Packs == nil {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
}

func TestImportExtensionPackReturnsTheType(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"importExtension":{"id":"ext-example","name":"Example Cloud","fields":[]}}}`)
	_, out, err := newTools(gw.URL, nil).importExtensionPack(context.Background(), callReq("Bearer t"), importExtensionPackIn{ID: "ext-example"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Type.ID != "ext-example" || out.Type.Name != "Example Cloud" {
		t.Fatalf("Type = %+v", out.Type)
	}
	if gw.auth.Load() != "Bearer t" {
		t.Fatalf("Authorization = %v", gw.auth.Load())
	}
}

func TestImportExtensionPackNeedsAnID(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	_, _, err := newTools(gw.URL, nil).importExtensionPack(context.Background(), callReq("Bearer t"), importExtensionPackIn{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("err = %v", err)
	}
	if gw.calls.Load() != 0 {
		t.Fatal("the gateway must not be called")
	}
}

// The MCP makes no access decision: the vault's refusal comes back as it is.
func TestImportExtensionPackRelaysTheRefusal(t *testing.T) {
	gw := fakeGateway(t, `{"errors":[{"message":"this needs a site admin","extensions":{"code":"PERMISSION_DENIED","reason":"NOT_SITE_ADMIN"}}]}`)
	_, _, err := newTools(gw.URL, nil).importExtensionPack(context.Background(), callReq("Bearer t"), importExtensionPackIn{ID: "ext-example"})
	if err == nil || !strings.Contains(err.Error(), "site admin") {
		t.Fatalf("err = %v", err)
	}
}

func TestImportExtensionPackNeedsABearer(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	if _, _, err := newTools(gw.URL, nil).importExtensionPack(context.Background(), callReq(""), importExtensionPackIn{ID: "ext-example"}); err == nil {
		t.Fatal("want an error")
	}
	if gw.calls.Load() != 0 {
		t.Fatal("the gateway must not be called")
	}
}
