// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"testing"

	buildinfo "github.com/Bugs5382/go-buildinfo"
)

func stampBuild(t *testing.T) {
	t.Helper()
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })
}

func TestVersionDefaultsToTheBuildStamp(t *testing.T) {
	t.Setenv("SERVICE_VERSION", "")
	stampBuild(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "v9.9.9-test" {
		t.Fatalf("Version = %q, want the build stamp", cfg.Version)
	}
}

func TestReadyzReportsTheBuild(t *testing.T) {
	stampBuild(t)
	f := newFakeDeps(t)
	code, body := probe(t, healthMux(t, testChecker(t, config{GatewayURL: f.srv.URL + "/machine/graphql", AcceptAPITokens: true})), "/readyz")
	if code != http.StatusOK || body.Build.Version != "v9.9.9-test" || body.Build.Commit != "0123456789abcdef" {
		t.Fatalf("GET /readyz = %d %+v", code, body)
	}
}

func TestBuildCommitFallsBack(t *testing.T) {
	old := buildinfo.Commit
	buildinfo.Commit = ""
	t.Cleanup(func() { buildinfo.Commit = old })
	if c := buildinfo.Get().Commit; c == "" {
		t.Fatal("commit is empty, want the VCS revision or unknown")
	}
}
