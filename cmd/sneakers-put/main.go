// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-put creates a Sneakers secret, or updates fields of an
// existing one, reading values from files or stdin on this machine, so a
// value never passes through an agent session or the shell history.
//
//	SNEAKERS_URL=https://sneakers.example.org SNEAKERS_TOKEN=snk_u_... \
//	  sneakers-put -folder <id> -type <id> -name <name> -field password=@pw.txt -field username=svc
//	sneakers-put -id <secret id> -field password=-
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/cliauth"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
	"github.com/Sneakers-PAM/sneakers-mcp/internal/secretput"
)

type config struct {
	endpoint string
	req      secretput.Request
}

// rawFields collects -field arguments unparsed: the flag package would quote
// a rejected argument in its error, and that argument may be a pasted value.
type rawFields []string

func (r *rawFields) String() string     { return "" }
func (r *rawFields) Set(v string) error { *r = append(*r, v); return nil }

const usageText = `sneakers-put creates a Sneakers secret, or updates fields of an existing one,
with values read from files or stdin, so a value never passes through an
agent session or the shell history.

Usage:
  sneakers-put -folder <folder id> -type <type id> -name <name> [-disable-rotation] [-keep-folder] -field ... [-field ...]
  sneakers-put -id <secret id> -field ... [-field ...]

Create mode (-folder, -type, -name) makes a new secret. Update mode (-id)
writes a new version of an existing secret with the fields given.

A new secret whose name, or a username, login, email or account field, names
you goes to your Personal folder instead of -folder, unless you pass
-keep-folder. The output then says which folder it went to and why.

Flags:
  -folder <id>          create: destination folder id
  -type <id>            create: secret type id
  -name <name>          create: name of the new secret
  -disable-rotation     create: store the secret with rotation turned off
  -keep-folder          create: use -folder even when the secret names you
  -id <id>              update: id of the secret to update
  -field <spec>         a field to set; repeatable, at least one
  -insecure-localhost   allow an http:// SNEAKERS_URL on localhost (testing only)
  -h, -help             print this help

Field forms:
  key=@file   read the value from file
  key=-       read the value from stdin; only one field per call may use it
  key=value   the value itself, for non-sensitive fields only (TEXT,
              BOOLEAN, SELECT); a sensitive field given this way is refused

Environment:
  SNEAKERS_URL     Sneakers base URL; must be https://
  SNEAKERS_TOKEN   your personal token from /login (snk_u_...)

Examples:
  sneakers-put -folder <folder id> -type <type id> -name "router-01 admin" \
    -field username=admin -field password=@./router-01.pw
  sneakers-put -id <secret id> -field password=- < ./new.pw
`

type flags struct {
	folder, typ, name, id          *string
	disableRotation, insecureLocal *bool
	keepFolder                     *bool
	raw                            *rawFields
}

func newFlags() (*flag.FlagSet, flags) {
	fs := flag.NewFlagSet("sneakers-put", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := flags{
		folder:          fs.String("folder", "", "create: destination folder id"),
		typ:             fs.String("type", "", "create: secret type id"),
		name:            fs.String("name", "", "create: name of the new secret"),
		id:              fs.String("id", "", "update: id of the secret to update"),
		disableRotation: fs.Bool("disable-rotation", false, "create: turn rotation off"),
		keepFolder:      fs.Bool("keep-folder", false, "create: keep -folder even when the secret names you"),
		insecureLocal:   fs.Bool("insecure-localhost", false, "allow http:// to localhost (testing only)"),
		raw:             &rawFields{},
	}
	fs.Var(f.raw, "field", "key=@file, key=- (stdin) or key=value (non-secret fields only); repeatable")
	return fs, f
}

func parse(args []string, getenv func(string) string) (config, error) {
	fs, f := newFlags()
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, errors.New("unexpected arguments after the flags")
	}
	endpoint, token, err := cliauth.FromEnv(getenv, *f.insecureLocal)
	if err != nil {
		return config{}, err
	}
	if err := checkMode(*f.id, *f.folder, *f.typ, *f.name, *f.disableRotation || *f.keepFolder); err != nil {
		return config{}, err
	}
	specs := make([]secretput.FieldSpec, 0, len(*f.raw))
	for i, r := range *f.raw {
		spec, err := secretput.ParseField(r)
		if err != nil {
			return config{}, fmt.Errorf("-field #%d: %w", i+1, err)
		}
		specs = append(specs, spec)
	}
	if err := secretput.CheckSpecs(specs); err != nil {
		return config{}, err
	}
	return config{endpoint: endpoint, req: secretput.Request{
		Token: token, FolderID: *f.folder, TypeID: *f.typ, Name: *f.name, DisableRotation: *f.disableRotation, KeepFolder: *f.keepFolder,
		SecretID: *f.id, Fields: specs,
	}}, nil
}

func checkMode(id, folder, typ, name string, createOptions bool) error {
	if id != "" {
		if folder != "" || typ != "" || name != "" || createOptions {
			return errors.New("-id updates a secret; -folder, -type, -name, -disable-rotation and -keep-folder are for a create")
		}
		return nil
	}
	if folder == "" || typ == "" || name == "" {
		return errors.New("give -folder, -type and -name to create a secret, or -id to update one")
	}
	return nil
}

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	c, err := parse(args, getenv)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sneakers-put: %v\n\n%s", err, usageText)
		return 2
	}
	c.req.Stdin = stdin
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := secretput.Put(ctx, gwclient.New(c.endpoint, nil), c.req)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "sneakers-put:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "id: %s\nname: %s\n", res.ID, res.Name)
	if p := res.Placement; p != nil {
		_, _ = fmt.Fprintf(stdout, "folder: %s\nplacement: %s: %s\n", p.FolderID, p.Rule, p.Reason)
	}
	if c.req.SecretID != "" {
		_, _ = fmt.Fprintf(stdout, "changed: %s\n", strings.Join(res.Changed, ","))
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}
