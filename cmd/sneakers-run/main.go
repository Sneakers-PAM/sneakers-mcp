// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-run runs one command with a Sneakers secret supplied to
// it on stdin or in a private temp file. The value is released by the
// gateway for this exact command only: at once for a secret the user can
// read, or after an owner or approver approves it (or the user confirms the
// task once, when nobody else can) for a secret with an approval level. It is
// masked in the command's output.
//
//	export SNEAKERS_URL=https://sneakers.example.org
//	sneakers-run login
//	sneakers-run -secret <id> [-field password] [-inject stdin|file] [-run-id <id>] [-purpose <text>] [-no-open] -- <command> [args...]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/secretrun"
)

// tokenStore is where `login` keeps the personal token (the macOS
// Keychain, or on Linux the keyring or a 0600 file); the tests replace it.
var tokenStore = cliauth.DefaultStore()

// runIDEnv names the run id when -run-id isn't given.
const runIDEnv = "SNEAKERS_RUN_ID"

type config struct {
	endpoint string
	hc       *http.Client
	noOpen   bool
	opts     secretrun.Options
}

var usageText = `sneakers-run runs one command with a Sneakers secret field supplied to it on
stdin or in a private temp file. The gateway releases the value for this exact
command only: at once for a secret you can read, or, for a secret with an
approval level, after an owner or approver approves it (or you confirm the
task once, when nobody else can). The value is masked in the command's output.

Usage:
  sneakers-run -secret <secret id> [flags] -- <command> [args...]
` + cliauth.LoginUsage("sneakers-run") + `
Flags:
  -secret <id>          id of the secret to use (required)
  -field <key>          field of the secret to supply (default: password)
  -inject stdin|file    stdin: send the value on the command's stdin (default);
                        file: write it to a 0600 temp file, named by
                        {secret_file} in the args and $SNEAKERS_SECRET_FILE
  -label <text>         shown on the approval page (default: this host's name)
  -run-id <id>          put this use on the same approval page as the other
                        uses of run <id> (default: $SNEAKERS_RUN_ID, else a
                        new run for this command)
  -purpose <text>       one line saying what the command is for, shown on the
                        approval page
  -no-open              print the approval link without opening a browser
  -ca-file <pem>        also trust the certificates in this PEM file for
                        SNEAKERS_URL, such as a new appliance's own
  -insecure-localhost   allow an http:// SNEAKERS_URL on localhost (testing only)
  -h, -help             print this help

Everything after -- is the command, run exactly as given.

Environment:
  SNEAKERS_URL     Sneakers base URL; must be https://
  SNEAKERS_TOKEN   a personal token (snk_u_...) to use instead of the one
                   sneakers-run login stored; not passed to the command
  SNEAKERS_CA_FILE PEM file of extra certificates to trust, used when
                   -ca-file isn't given
  SNEAKERS_RUN_ID  run id used when -run-id isn't given ([A-Za-z0-9_-],
                   at most 64 characters)
  BROWSER          browser used to open the approval page and the sign-in
                   (else xdg-open or open)

Examples:
  sneakers-run login
  sneakers-run -secret <secret id> -- ssh admin@router-01
  sneakers-run -inject file -secret <secret id> -- tool --key {secret_file}
  SNEAKERS_RUN_ID=run_deploy1 sneakers-run -purpose "deploy the app" -secret <secret id> -- tool
`

type flags struct {
	secret, field, inject, label, runID, purpose *string
	caFile                                       *string
	insecureLocal, noOpen                        *bool
}

func newFlags() (*flag.FlagSet, flags) {
	fs := flag.NewFlagSet("sneakers-run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, flags{
		secret:        fs.String("secret", "", "secret id"),
		field:         fs.String("field", "password", "field key"),
		inject:        fs.String("inject", string(secretrun.InjectStdin), "stdin or file"),
		label:         fs.String("label", "", "shown on the approval page (default: host name)"),
		runID:         fs.String("run-id", "", "run id shared with the other uses on one approval page"),
		purpose:       fs.String("purpose", "", "shown to the owner on the approval page"),
		insecureLocal: fs.Bool("insecure-localhost", false, "allow http:// to localhost (testing only)"),
		noOpen:        fs.Bool("no-open", false, "print the approval link without opening a browser"),
		caFile:        fs.String("ca-file", "", "PEM file of extra roots to trust for SNEAKERS_URL"),
	}
}

func parse(args []string, getenv func(string) string) (config, error) {
	fs, f := newFlags()
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	secret, field, inject, label, insecureLocal, noOpen := f.secret, f.field, f.inject, f.label, f.insecureLocal, f.noOpen
	endpoint, token, err := cliauth.Resolve(getenv, *insecureLocal, tokenStore)
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
	runID := *f.runID
	if runID == "" {
		runID = getenv(runIDEnv)
	}
	if runID != "" && !gwclient.ValidRunID(runID) {
		return config{}, fmt.Errorf("-run-id or %s must be 1 to 64 letters, digits, '_' or '-'", runIDEnv)
	}
	hc, err := cliauth.HTTPClient(cliauth.CAFile(*f.caFile, getenv))
	if err != nil {
		return config{}, err
	}
	return config{
		endpoint: endpoint,
		hc:       hc,
		noOpen:   *noOpen,
		opts: secretrun.Options{
			Token: token, SecretID: *secret, FieldKey: *field, Label: *label, RunID: runID, Purpose: *f.purpose,
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
	if cliauth.IsAuth(args) {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return cliauth.RunAuth(ctx, cliauth.Session{
			Prog: "sneakers-run", Getenv: getenv, Store: tokenStore, Stdout: stdout, Stderr: stderr, HostName: cliauth.HostName,
			Opener: func() func(string) { return secretrun.StartOpener(secretrun.FindOpener(getenv, exec.LookPath)) },
		}, args)
	}
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
	code, err := secretrun.Run(ctx, gwclient.New(c.endpoint, c.hc), c.opts)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sneakers-run:", err)
		return 1
	}
	return code
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
