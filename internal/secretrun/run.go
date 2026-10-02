// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package secretrun runs a command with one secret field supplied to it,
// without the value ever passing through the caller: the gateway releases it
// only for the exact command a human approved.
package secretrun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// Inject is how the value reaches the command.
type Inject string

const (
	InjectStdin Inject = "stdin"
	InjectFile  Inject = "file"

	// FilePlaceholder in argv is replaced by the temp file path under InjectFile.
	FilePlaceholder = "{secret_file}"
	// FileEnv also carries the temp file path under InjectFile.
	FileEnv = "SNEAKERS_SECRET_FILE"
	// TokenEnv holds the personal token; it is never passed to the command.
	TokenEnv = "SNEAKERS_TOKEN"
)

// ErrArgvMismatch means the gateway released the value for a different
// command than the one asked to run.
var ErrArgvMismatch = errors.New("approved command differs from the requested command")

// Gateway is the slice of gwclient.Client the runner needs.
type Gateway interface {
	PrepareSecretUse(ctx context.Context, token, secretID, fieldKey string, argv []string, clientLabel string) (gwclient.SecretUse, error)
	SecretUse(ctx context.Context, token, id string) (gwclient.SecretUse, error)
	RedeemSecretUse(ctx context.Context, token, id string) (string, gwclient.SecretUse, error)
}

type Options struct {
	Token, SecretID, FieldKey, Label string
	Argv                             []string
	Inject                           Inject
	PollInterval                     time.Duration
	Stdout, Stderr                   io.Writer
	// Open shows the approval page to the user; nil leaves it to the printed link.
	Open func(url string)
}

// Run asks for the use, waits for it to be approved, and runs the command.
// It returns the command's exit code.
func Run(ctx context.Context, gw Gateway, o Options) (int, error) {
	if len(o.Argv) == 0 {
		return 0, errors.New("no command given")
	}
	program, err := resolveProgram(o.Argv[0])
	if err != nil {
		return 0, err
	}
	use, err := gw.PrepareSecretUse(ctx, o.Token, o.SecretID, o.FieldKey, o.Argv, o.Label)
	if err != nil {
		return 0, fmt.Errorf("prepare: %w", err)
	}
	if use.State == "PENDING" {
		_, _ = fmt.Fprintf(o.Stderr, "sneakers-run: approve this use of %s at %s\n", use.SecretName, use.ApprovalURL)
		if o.Open != nil {
			o.Open(use.ApprovalURL)
		}
	}
	for use.State == "PENDING" {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(o.PollInterval):
		}
		if use, err = gw.SecretUse(ctx, o.Token, use.ID); err != nil {
			return 0, fmt.Errorf("poll: %w", err)
		}
	}
	if use.State != "APPROVED" {
		return 0, fmt.Errorf("use was not approved: %s", strings.ToLower(use.State))
	}
	value, redeemed, err := gw.RedeemSecretUse(ctx, o.Token, use.ID)
	if err != nil {
		return 0, fmt.Errorf("redeem: %w", err)
	}
	// Run what the server bound, and only if it is what was asked for.
	if !slices.Equal(redeemed.Argv, o.Argv) {
		return 0, ErrArgvMismatch
	}
	return execute(ctx, program, redeemed.Argv, value, o)
}

func execute(ctx context.Context, program string, argv []string, value string, o Options) (int, error) {
	env := childEnv()
	args := append([]string{}, argv...)
	var stdin io.Reader
	switch o.Inject {
	case InjectFile:
		path, err := writePrivate(value)
		if err != nil {
			return 0, err
		}
		defer func() { _ = os.Remove(path) }()
		for i := range args {
			args[i] = strings.ReplaceAll(args[i], FilePlaceholder, path)
		}
		env = append(env, FileEnv+"="+path)
	default:
		stdin = strings.NewReader(value + "\n")
	}

	stdout, stderr := newMasker(o.Stdout, value), newMasker(o.Stderr, value)
	cmd := exec.CommandContext(ctx, program, args[1:]...) // #nosec G204 -- runs exactly the command the owner approved
	cmd.Args[0] = args[0]
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, stdin, stdout, stderr
	runErr := cmd.Run()
	if err := errors.Join(stdout.Close(), stderr.Close()); err != nil {
		return 0, err
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if runErr != nil {
		return 0, runErr
	}
	return 0, nil
}

func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, TokenEnv+"=") {
			env = append(env, kv)
		}
	}
	return env
}

// writePrivate stores the value in a file only this user can read.
func writePrivate(value string) (string, error) {
	f, err := os.CreateTemp("", "sneakers-run-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	err = f.Chmod(0o600)
	if err == nil {
		_, err = f.WriteString(value)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write secret file: %w", err)
	}
	return path, nil
}
