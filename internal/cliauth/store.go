// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"fmt"
	"net/url"
	"strings"
)

// Store keeps one personal token per gateway, by Account.
type Store interface {
	// Get returns the token for account; ok is false when there is none.
	Get(account string) (token string, ok bool, err error)
	// Set stores token for account, replacing any token there.
	Set(account, token string) error
	// Delete removes account's token; removing none is no error.
	Delete(account string) error
}

// KeychainService is the macOS Keychain service the tokens are kept under,
// one item per gateway host.
const KeychainService = "Sneakers-PAM"

// DefaultStore is where `login` keeps the token on this system: the login
// Keychain on macOS. It is nil where there's no store, and then only
// SNEAKERS_TOKEN gives a token.
func DefaultStore() Store { return defaultStore() }

// Account is the store's name for a gateway: its host, with the port when
// the URL has one, in lower case.
func Account(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%s %q is not an absolute URL", URLEnv, base)
	}
	return strings.ToLower(u.Host), nil
}
