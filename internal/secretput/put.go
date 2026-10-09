// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// Gateway is the slice of gwclient.Client a put needs.
type Gateway interface {
	ListSecretTypes(ctx context.Context, token string) ([]gwclient.SecretType, error)
	FindSecrets(ctx context.Context, token, query, folderID, typeID string) ([]gwclient.SecretSummary, error)
	CreateSecret(ctx context.Context, token, folderID, typeID, name string, fields []gwclient.Field, targetID string, auto ...gwclient.Automation) (*gwclient.SecretSummary, error)
	UpdateSecretFields(ctx context.Context, token, id string, fields []gwclient.Field) (*gwclient.SecretSummary, []string, error)
}

// Request is a create (FolderID, TypeID, Name) or, when SecretID is set, an
// update of that secret's fields.
type Request struct {
	Token string

	FolderID, TypeID, Name string
	DisableRotation        bool
	// KeepFolder keeps FolderID for a secret that names its caller, which the
	// gateway would otherwise store in the caller's Personal folder.
	KeepFolder bool

	SecretID string

	Fields []FieldSpec
	Stdin  io.Reader
}

// Result carries no values.
type Result struct {
	ID, Name string
	Changed  []string
	// Placement is set on a create: where the gateway stored it and why.
	Placement *gwclient.Placement
}

// plainKinds may be given as a literal. Anything else, including a key the
// type does not declare, could hold a secret.
var plainKinds = map[string]bool{"TEXT": true, "BOOLEAN": true, "SELECT": true}

// Put checks literals against the secret type, reads the other values, and
// creates or updates the secret.
func Put(ctx context.Context, gw Gateway, r Request) (Result, error) {
	if err := CheckSpecs(r.Fields); err != nil {
		return Result{}, err
	}
	if err := checkLiterals(ctx, gw, r); err != nil {
		return Result{}, err
	}
	fields, secrets, err := readValues(r)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if r.SecretID != "" {
		s, keys, uerr := gw.UpdateSecretFields(ctx, r.Token, r.SecretID, fields)
		if uerr == nil {
			res = Result{ID: s.ID, Name: s.Name, Changed: keys}
		}
		err = uerr
	} else {
		s, cerr := gw.CreateSecret(ctx, r.Token, r.FolderID, r.TypeID, r.Name, fields, "",
			gwclient.Automation{DisableRotation: r.DisableRotation, KeepFolder: r.KeepFolder})
		if cerr == nil {
			res = Result{ID: s.ID, Name: s.Name, Placement: s.Placement}
		}
		err = cerr
	}
	if err != nil {
		return Result{}, redact(err, secrets)
	}
	return res, nil
}

func checkLiterals(ctx context.Context, gw Gateway, r Request) error {
	var literals []string
	for _, f := range r.Fields {
		if f.Source == SourceLiteral {
			literals = append(literals, f.Key)
		}
	}
	if len(literals) == 0 {
		return nil
	}
	typeID := r.TypeID
	if r.SecretID != "" {
		var err error
		if typeID, err = secretType(ctx, gw, r.Token, r.SecretID); err != nil {
			return err
		}
	}
	kinds, err := fieldKinds(ctx, gw, r.Token, typeID)
	if err != nil {
		return err
	}
	for _, k := range literals {
		kind, declared := kinds[k]
		if plainKinds[strings.ToUpper(kind)] {
			continue
		}
		why := fmt.Sprintf("is not declared by type %s", typeID)
		if declared {
			why = fmt.Sprintf("is a %s field of type %s", strings.ToUpper(kind), typeID)
		}
		return fmt.Errorf("field %q %s, so it may hold a secret: pass it as %s=@file or %s=-, never on the command line", k, why, k, k)
	}
	return nil
}

func secretType(ctx context.Context, gw Gateway, token, id string) (string, error) {
	found, err := gw.FindSecrets(ctx, token, "", "", "")
	if err != nil {
		return "", fmt.Errorf("look up secret %s: %w", id, err)
	}
	for _, s := range found {
		if s.ID == id {
			return s.TypeID, nil
		}
	}
	return "", fmt.Errorf("secret %s is not visible to this token, so its field kinds can't be checked: pass every field as key=@file or key=-", id)
}

func fieldKinds(ctx context.Context, gw Gateway, token, typeID string) (map[string]string, error) {
	types, err := gw.ListSecretTypes(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("list secret types: %w", err)
	}
	for _, ty := range types {
		if ty.ID != typeID {
			continue
		}
		kinds := make(map[string]string, len(ty.Fields))
		for _, f := range ty.Fields {
			kinds[f.Key] = f.Kind
		}
		return kinds, nil
	}
	return nil, fmt.Errorf("unknown secret type %s", typeID)
}

// readValues returns the fields to send and the values that came from a file
// or stdin, for redaction.
func readValues(r Request) ([]gwclient.Field, []string, error) {
	fields := make([]gwclient.Field, 0, len(r.Fields))
	var secrets []string
	for _, f := range r.Fields {
		if f.Source == SourceLiteral {
			fields = append(fields, gwclient.Field{Key: f.Key, Value: f.Literal})
			continue
		}
		v, err := readValue(f, r.Stdin)
		if err != nil {
			return nil, nil, err
		}
		fields = append(fields, gwclient.Field{Key: f.Key, Value: v})
		secrets = append(secrets, v)
	}
	return fields, secrets, nil
}

func readValue(f FieldSpec, stdin io.Reader) (string, error) {
	var src io.Reader
	if f.Source == SourceStdin {
		if stdin == nil {
			return "", fmt.Errorf("field %q: no stdin", f.Key)
		}
		src = stdin
	} else {
		fh, err := os.Open(f.Path)
		if err != nil {
			return "", fmt.Errorf("field %q: %w", f.Key, err)
		}
		defer func() { _ = fh.Close() }()
		src = fh
	}
	b, err := io.ReadAll(io.LimitReader(src, maxFieldValueLen+1))
	if err != nil {
		return "", fmt.Errorf("field %q: read failed", f.Key)
	}
	if len(b) > maxFieldValueLen {
		return "", fmt.Errorf("field %q: value exceeds %d bytes", f.Key, maxFieldValueLen)
	}
	v := trimNewline(string(b))
	if v == "" {
		return "", fmt.Errorf("field %q: value is empty", f.Key)
	}
	return v, nil
}

// trimNewline drops the one line ending that echo and editors add.
func trimNewline(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	return strings.TrimSuffix(s, "\n")
}

// redact keeps a gateway message that quotes a value from printing it.
func redact(err error, secrets []string) error {
	msg := err.Error()
	// Longest first, so a value that contains another is removed whole.
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	for _, s := range secrets {
		msg = strings.ReplaceAll(msg, s, "[redacted]")
	}
	return errors.New(msg)
}
