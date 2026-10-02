// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"strings"
	"testing"
)

// Values passed to create or generate land in the agent's transcript, so both
// descriptions must send agents to the local sneakers-put instead.
func TestCreateAndGenerateDescriptionsSteerValuesToSneakersPut(t *testing.T) {
	seen := 0
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolCreate && tl.Name != toolGenerate {
			continue
		}
		seen++
		if !strings.Contains(tl.Description, "sneakers-put") || !strings.Contains(tl.Description, "transcript") {
			t.Errorf("%s description does not steer values to sneakers-put: %q", tl.Name, tl.Description)
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 tools", seen)
	}
}
