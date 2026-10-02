// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

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
