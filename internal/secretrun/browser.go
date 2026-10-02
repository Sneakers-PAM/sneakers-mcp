// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"os/exec"
	"strings"
)

// BrowserEnv names the user's browser: a command with optional arguments, or a
// ':'-separated list of them, where "%s" marks the URL.
const BrowserEnv = "BROWSER"

var fallbackOpeners = []string{"xdg-open", "open"}

// FindOpener returns the command to open a URL with: the first $BROWSER entry
// whose program exists, else the first of xdg-open or open on PATH. It returns
// nil when there is none.
func FindOpener(getenv func(string) string, lookPath func(string) (string, error)) []string {
	for _, entry := range strings.Split(getenv(BrowserEnv), ":") {
		if f := strings.Fields(entry); len(f) > 0 {
			if p, err := lookPath(f[0]); err == nil {
				return append([]string{p}, f[1:]...)
			}
		}
	}
	for _, name := range fallbackOpeners {
		if p, err := lookPath(name); err == nil {
			return []string{p}
		}
	}
	return nil
}

func openerArgv(opener []string, url string) []string {
	argv := append([]string{}, opener...)
	placed := false
	for i := 1; i < len(argv); i++ {
		if strings.Contains(argv[i], "%s") {
			argv[i] = strings.ReplaceAll(argv[i], "%s", url)
			placed = true
		}
	}
	if !placed {
		argv = append(argv, url)
	}
	return argv
}

// StartOpener returns an Open func that starts opener on the URL without
// waiting for it, or nil when opener is empty.
func StartOpener(opener []string) func(url string) {
	if len(opener) == 0 {
		return nil
	}
	return func(url string) {
		argv := openerArgv(opener, url)
		cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the user's own configured browser
		cmd.Env = childEnv()
		detach(cmd)
		if cmd.Start() == nil {
			go func() { _ = cmd.Wait() }()
		}
	}
}
