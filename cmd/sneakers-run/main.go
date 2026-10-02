// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-run runs one command with a Sneakers secret supplied to
// it on stdin or in a private temp file. The value is released by the
// gateway only after the token's owner approves this exact command (or a
// grant they created covers it), and it is masked in the command's output.
//
//	SNEAKERS_URL=https://sneakers.example.org SNEAKERS_TOKEN=snk_u_... \
//	  sneakers-run -secret <id> [-field password] [-inject stdin|file] [-no-open] -- <command> [args...]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/secretrun"
)

type config struct {
	endpoint string
	noOpen   bool
	opts     secretrun.Options
}

const usageText = `sneakers-run runs one command with a Sneakers secret field supplied to it on
stdin or in a private temp file. The gateway releases the value only after the
token's owner approves this exact command (or a grant they created covers
it), and the value is masked in the command's output.

Usage:
  sneakers-run -secret <secret id> [flags] -- <command> [args...]

Flags:
  -secret <id>          id of the secret to use (required)
  -field <key>          field of the secret to supply (default: password)
  -inject stdin|file    stdin: send the value on the command's stdin (default);
                        file: write it to a 0600 temp file, named by
                        {secret_file} in the args and $SNEAKERS_SECRET_FILE
  -label <text>         shown on the approval page (default: this host's name)
  -no-open              print the approval link without opening a browser
  -insecure-localhost   allow an http:// SNEAKERS_URL on localhost (testing only)
  -h, -help             print this help

Everything after -- is the command, run exactly as given.

Environment:
  SNEAKERS_URL     Sneakers base URL; must be https://
  SNEAKERS_TOKEN   your personal token from /login (snk_u_...); not passed
                   to the command
  BROWSER          browser used to open the approval page (else xdg-open
                   or open)

Examples:
  sneakers-run -secret <secret id> -- ssh admin@router-01
  sneakers-run -inject file -secret <secret id> -- tool --key {secret_file}
`

type flags struct {
	secret, field, inject, label *string
	insecureLocal, noOpen        *bool
}

func newFlags() (*flag.FlagSet, flags) {
	fs := flag.NewFlagSet("sneakers-run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, flags{
		secret:        fs.String("secret", "", "secret id"),
		field:         fs.String("field", "password", "field key"),
		inject:        fs.String("inject", string(secretrun.InjectStdin), "stdin or file"),
		label:         fs.String("label", "", "shown on the approval page (default: host name)"),
		insecureLocal: fs.Bool("insecure-localhost", false, "allow http:// to localhost (testing only)"),
		noOpen:        fs.Bool("no-open", false, "print the approval link without opening a browser"),
	}
}

func parse(args []string, getenv func(string) string) (config, error) {
	fs, f := newFlags()
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	secret, field, inject, label, insecureLocal, noOpen := f.secret, f.field, f.inject, f.label, f.insecureLocal, f.noOpen
	endpoint, token, err := cliauth.FromEnv(getenv, *insecureLocal)
	switch {
	case err != nil:
		return config{}, err
	case *secret == "":
		return config{}, errors.New("-secret is required")
	case fs.NArg() == 0:
		return config{}, errors.New("no command given after --")
	}
	mode := secretrun.Inject(*inject)
	if mode != secretrun.InjectStdin && mode != secretrun.InjectFile {
		return config{}, fmt.Errorf("-inject must be stdin or file, not %q", *inject)
	}
	if *label == "" {
		*label, _ = os.Hostname()
	}
	return config{
		endpoint: endpoint,
		noOpen:   *noOpen,
		opts: secretrun.Options{
			Token: token, SecretID: *secret, FieldKey: *field, Label: *label,
			Argv: fs.Args(), Inject: mode, PollInterval: 2 * time.Second,
		},
	}, nil
}

// opener returns how to show the approval page, or nil to only print it.
func opener(c config, getenv func(string) string, lookPath func(string) (string, error)) func(string) {
	if c.noOpen {
		return nil
	}
	return secretrun.StartOpener(secretrun.FindOpener(getenv, lookPath))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	c, err := parse(args, getenv)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sneakers-run: %v\n\n%s", err, usageText)
		return 2
	}
	c.opts.Stdout, c.opts.Stderr = stdout, stderr
	c.opts.Open = opener(c, getenv, exec.LookPath)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, err := secretrun.Run(ctx, gwclient.New(c.endpoint, nil), c.opts)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sneakers-run:", err)
		return 1
	}
	return code
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
