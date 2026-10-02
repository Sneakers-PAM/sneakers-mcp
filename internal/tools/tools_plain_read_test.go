// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestGetSecretDescriptionSaysPlainFieldsAreReadAndAudited(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolGet {
			continue
		}
		d := strings.ToLower(tl.Description)
		for _, want := range []string{"non-sensitive", "notes", "url", "endpoint", "audited as a read"} {
			if !strings.Contains(d, want) {
				t.Fatalf("description lacks %q: %q", want, tl.Description)
			}
		}
		if !strings.Contains(d, "sensitive field") || !strings.Contains(d, "approv") {
			t.Fatalf("description must tie approval to sensitive fields: %q", tl.Description)
		}
		return
	}
	t.Fatalf("%s not registered", toolGet)
}

func TestGetSecretOfAPlainFieldNeverPreparesAReveal(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"notes", "rotated by the DBA team"},
		{"url", "https://db.example.org:5432"},
		{"endpoint", "db.example.org"},
		{"notes", ""},
	} {
		gw := newRouteGateway(t, map[string]string{
			"revealSecretFieldForPrincipal": `{"data":{"revealSecretFieldForPrincipal":"` + tc.value + `"}}`,
			"prepareSecretUse":              useBody("prepareSecretUse", "PENDING"),
		})
		_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer snk_u_tok"), getSecretIn{ID: "s1", FieldKey: tc.key})
		if err != nil || out.Value != tc.value || out.ApprovalRequired || out.UseID != "" || out.ApprovalURL != "" {
			t.Fatalf("%s: out = %+v err = %v, want the plain value", tc.key, out, err)
		}
		gw.mu.Lock()
		seen := slices.Clone(gw.seen)
		gw.mu.Unlock()
		if !slices.Equal(seen, []string{"revealSecretFieldForPrincipal"}) {
			t.Fatalf("%s: gateway calls = %v, want only the read", tc.key, seen)
		}
	}
}

func TestGetSecretFieldKeySchemaNamesPlainFields(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolGet {
			continue
		}
		var sch struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		b, _ := json.Marshal(tl.InputSchema)
		if err := json.Unmarshal(b, &sch); err != nil {
			t.Fatal(err)
		}
		if d := sch.Properties["fieldKey"].Description; !strings.Contains(d, "notes") {
			t.Fatalf("fieldKey description = %q, want it to name a plain field", d)
		}
		return
	}
	t.Fatalf("%s not registered", toolGet)
}
