// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package cliauth holds the environment rules the local Sneakers commands
// share: a personal token and an https gateway URL.
package cliauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	// TokenEnv holds the caller's personal token.
	TokenEnv = "SNEAKERS_TOKEN"
	// URLEnv holds the Sneakers base URL.
	URLEnv = "SNEAKERS_URL"

	personalTokenPrefix = "snk_u_"
)

// FromEnv returns the machine GraphQL endpoint and the personal token.
// Service-account tokens are refused: these commands act for a person.
func FromEnv(getenv func(string) string, insecureLocal bool) (endpoint, token string, err error) {
	token, base := getenv(TokenEnv), strings.TrimRight(getenv(URLEnv), "/")
	switch {
	case !strings.HasPrefix(token, personalTokenPrefix):
		return "", "", errors.New(TokenEnv + " must hold a personal token (" + personalTokenPrefix + "...)")
	case base == "":
		return "", "", errors.New(URLEnv + " is not set")
	}
	if err := checkURL(base, insecureLocal); err != nil {
		return "", "", err
	}
	return base + "/machine/graphql", token, nil
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
