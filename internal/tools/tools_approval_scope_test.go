// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"strings"
	"testing"
)

func TestApprovalToolDescriptionsLimitTokenApprovalToPersonalTokens(t *testing.T) {
	want := map[string][]string{
		toolGet:    {"personal token", "service-account", "allow api access to sensitive secrets"},
		toolRedeem: {"personal token"},
	}
	seen := 0
	for _, tl := range listRegisteredTools(t) {
		phrases, ok := want[tl.Name]
		if !ok {
			continue
		}
		seen++
		d := strings.ToLower(tl.Description)
		for _, p := range phrases {
			if !strings.Contains(d, p) {
				t.Errorf("%s description lacks %q: %q", tl.Name, p, tl.Description)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("found %d of %d approval tools", seen, len(want))
	}
}
