// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package cliauth holds what the local Sneakers commands share: the gateway
// URL, the personal token they act with, and the sign-in that gets one.
package cliauth

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// TokenEnv holds the caller's personal token, which wins over a stored
	// one.
	TokenEnv = "SNEAKERS_TOKEN"
	// URLEnv holds the Sneakers base URL.
	URLEnv = "SNEAKERS_URL"

	personalTokenPrefix = "snk_u_"
)

// personalToken is a personal token's whole shape: the prefix and a
// 43-character base64url body.
var personalToken = regexp.MustCompile(`^snk_u_[A-Za-z0-9_-]{43}$`)

// Base returns the Sneakers base URL from the environment, without its
// trailing slash, once it is https (or http to this machine with
// insecureLocal).
func Base(getenv func(string) string, insecureLocal bool) (string, error) {
	base := strings.TrimRight(getenv(URLEnv), "/")
	if base == "" {
		return "", errors.New(URLEnv + " is not set")
	}
	if err := checkURL(base, insecureLocal); err != nil {
		return "", err
	}
	return base, nil
}

// Resolve returns the machine GraphQL endpoint and the personal token: the
// one in SNEAKERS_TOKEN, else the one `login` stored for this gateway.
// Service-account tokens are refused: these commands act for a person.
func Resolve(getenv func(string) string, insecureLocal bool, store Store) (endpoint, token string, err error) {
	base, err := Base(getenv, insecureLocal)
	if err != nil {
		return "", "", err
	}
	if token = getenv(TokenEnv); token == "" {
		if token, err = stored(base, store); err != nil {
			return "", "", err
		}
	}
	if !strings.HasPrefix(token, personalTokenPrefix) {
		return "", "", errors.New(TokenEnv + " must hold a personal token (" + personalTokenPrefix + "...)")
	}
	return base + "/machine/graphql", token, nil
}

func stored(base string, store Store) (string, error) {
	account, err := Account(base)
	if err != nil {
		return "", err
	}
	noToken := fmt.Errorf("no personal token for %s: sign in with `sneakers-put login` (or `sneakers-run login`), or set %s", account, TokenEnv)
	if store == nil {
		return "", noToken
	}
	token, ok, err := store.Get(account)
	switch {
	case err != nil:
		return "", fmt.Errorf("read the stored token for %s: %w", account, err)
	case !ok:
		return "", noToken
	}
	return token, nil
}

// checkURL refuses anything but https, because the token and secret values
// cross this connection. Plain http is for a local gateway only.
func checkURL(base string, insecureLocal bool) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s %q is not an absolute URL", URLEnv, base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			if insecureLocal {
				return nil
			}
			return errors.New(URLEnv + " uses http; pass -insecure-localhost to allow it for a local gateway")
		}
	}
	return fmt.Errorf("%s must use https, not %q", URLEnv, u.Scheme)
}
