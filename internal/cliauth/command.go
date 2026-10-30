// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package cliauth

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// LoginTimeout bounds how long login waits for the person to sign in.
const LoginTimeout = 10 * time.Minute

// LoginUsage is the help for the login and logout subcommands, as prog.
func LoginUsage(prog string) string {
	return fmt.Sprintf(`  %[1]s login [-no-open] [-insecure-localhost]
  %[1]s logout

login signs you in to SNEAKERS_URL in your browser (the gateway's sign-in
and consent, with your second factor) and keeps the personal token it gets
in the macOS Keychain (service %[2]s, one item per gateway host), so
nobody copies a token. SNEAKERS_TOKEN, when set, still wins over it.
logout removes the stored token from the Keychain; revoke it on the Tokens
page to end it on the gateway too.
`, prog, KeychainService)
}

// Session is what the login and logout subcommands need from the command.
type Session struct {
	Prog   string
	Getenv func(string) string
	Store  Store
	// Opener returns how to open a URL in a browser, or nil to only print
	// it.
	Opener func() func(string)
	Stdout io.Writer
	Stderr io.Writer
	// HostName names this machine on the consent page.
	HostName func() (string, error)
}

// RunAuth runs `login` or `logout` (args[0]) and returns the exit code.
func RunAuth(ctx context.Context, s Session, args []string) int {
	fs := flag.NewFlagSet(s.Prog+" "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noOpen := fs.Bool("no-open", false, "print the sign-in link without opening a browser")
	insecureLocal := fs.Bool("insecure-localhost", false, "allow http:// to localhost (testing only)")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(s.Stdout, LoginUsage(s.Prog))
			return 0
		}
		_, _ = fmt.Fprintf(s.Stderr, "%s %s: unexpected arguments\n\n%s", s.Prog, args[0], LoginUsage(s.Prog))
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintf(s.Stderr, "%s %s: %v\n", s.Prog, args[0], err)
		return 1
	}
	base, err := Base(s.Getenv, *insecureLocal)
	if err != nil {
		return fail(err)
	}
	account, err := Account(base)
	if err != nil {
		return fail(err)
	}
	if s.Store == nil {
		return fail(errors.New("the token is kept in the macOS Keychain, which this system doesn't have; set " + TokenEnv + " instead"))
	}
	if args[0] == "logout" {
		if err := s.Store.Delete(account); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(s.Stdout, "Removed the stored token for %s.\n", account)
		return 0
	}
	host, _ := s.HostName()
	if host == "" {
		host = "this computer"
	}
	var open func(string)
	if !*noOpen && s.Opener != nil {
		open = s.Opener()
	}
	lctx, cancel := context.WithTimeout(ctx, LoginTimeout)
	defer cancel()
	token, err := Login(lctx, LoginOptions{Base: base, ClientName: s.Prog + " on " + host, Command: s.Prog, Open: open, Out: s.Stderr})
	if err != nil {
		return fail(err)
	}
	if err := s.Store.Set(account, token); err != nil {
		return fail(err)
	}
	_, _ = fmt.Fprintf(s.Stdout, "Signed in to %s. The token is in the macOS Keychain (service %s, account %s).\n", account, KeychainService, account)
	return 0
}

// IsAuth reports whether args start with the login or logout subcommand.
func IsAuth(args []string) bool {
	return len(args) > 0 && (args[0] == "login" || args[0] == "logout")
}

// HostName is os.Hostname, for Session.HostName.
func HostName() (string, error) { return os.Hostname() }
