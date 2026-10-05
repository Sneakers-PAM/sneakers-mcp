// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"context"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

func TestRunPassesTheRunIDAndPurposeThrough(t *testing.T) {
	gw := &fakeGateway{states: []string{"PENDING", "APPROVED"}, value: "v"}
	o, _, errb := opts("true")
	o.RunID, o.Purpose = "run_shared", "restart the cache"
	if code, err := Run(context.Background(), gw, o); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if gw.prepareRun != (gwclient.Run{ID: "run_shared", Purpose: "restart the cache"}) {
		t.Fatalf("run = %+v", gw.prepareRun)
	}
	if !strings.Contains(errb.String(), "run_shared") {
		t.Fatalf("the run id is not shown: %q", errb.String())
	}
}

func TestRunWithoutARunIDMintsOnePerInvocation(t *testing.T) {
	var ids []string
	for range 2 {
		gw := &fakeGateway{states: []string{"APPROVED"}, value: "v"}
		o, _, _ := opts("true")
		if _, err := Run(context.Background(), gw, o); err != nil {
			t.Fatal(err)
		}
		if !gwclient.ValidRunID(gw.prepareRun.ID) {
			t.Fatalf("run id %q", gw.prepareRun.ID)
		}
		ids = append(ids, gw.prepareRun.ID)
	}
	if ids[0] == ids[1] {
		t.Fatalf("two invocations shared run %q", ids[0])
	}
}
