// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
)

// TestMain keeps the tests off the real Keychain: with no store, only
// SNEAKERS_TOKEN gives a token.
func TestMain(m *testing.M) {
	tokenStore = nil
	os.Exit(m.Run())
}
