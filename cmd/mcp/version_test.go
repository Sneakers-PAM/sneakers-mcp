// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVersionDefaultsToTheBuildStamp(t *testing.T) {
	t.Setenv("SERVICE_VERSION", "")
	old := version
	version = "v9.9.9"
	t.Cleanup(func() { version = old })
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "v9.9.9" {
		t.Fatalf("Version = %q, want the build stamp", cfg.Version)
	}
}

func TestHealthReportsTheBuild(t *testing.T) {
	oldV, oldC := version, commit
	version, commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { version, commit = oldV, oldC })
	mux := newMux(http.NotFoundHandler(), func(h http.Handler) http.Handler { return h }, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body struct {
		Commit  string `json:"commit"`
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if rec.Code != http.StatusOK || body.Status != "ok" || body.Version != "v9.9.9-test" || body.Commit != "0123456789abcdef" {
		t.Fatalf("GET /health = %d %+v", rec.Code, body)
	}
}

func TestBuildCommitFallsBack(t *testing.T) {
	old := commit
	commit = ""
	t.Cleanup(func() { commit = old })
	if c := buildCommit(); c == "" {
		t.Fatal("buildCommit() is empty, want the VCS revision or unknown")
	}
}
