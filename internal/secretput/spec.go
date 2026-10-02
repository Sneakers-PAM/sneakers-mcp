// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package secretput creates or updates a Sneakers secret from values read
// on this machine, so a value never passes through an agent session.
package secretput

import (
	"errors"
	"fmt"
	"strings"
)

// Limits mirror what the MCP tools accept for one call.
const (
	maxFieldKeyLen   = 128
	maxFieldValueLen = 16 << 10
	maxFields        = 32
)

// Source is where a field's value comes from.
type Source int

const (
	SourceLiteral Source = iota // the value is on the command line: non-secret fields only
	SourceFile                  // key=@path
	SourceStdin                 // key=-
)

// FieldSpec is one parsed -field argument.
type FieldSpec struct {
	Key     string
	Source  Source
	Path    string
	Literal string
}

// ParseField parses key=@file, key=- or key=literal. Errors name the key,
// never the value.
func ParseField(s string) (FieldSpec, error) {
	key, val, ok := strings.Cut(s, "=")
	switch {
	case !ok:
		return FieldSpec{}, errors.New("a field must be key=@file, key=- or key=value")
	case strings.TrimSpace(key) == "":
		return FieldSpec{}, errors.New("a field key is empty")
	case len(key) > maxFieldKeyLen:
		return FieldSpec{}, fmt.Errorf("a field key exceeds %d bytes", maxFieldKeyLen)
	}
	switch {
	case val == "-":
		return FieldSpec{Key: key, Source: SourceStdin}, nil
	case strings.HasPrefix(val, "@"):
		if len(val) == 1 {
			return FieldSpec{}, fmt.Errorf("field %q: no file after @", key)
		}
		return FieldSpec{Key: key, Source: SourceFile, Path: val[1:]}, nil
	default:
		return FieldSpec{Key: key, Source: SourceLiteral, Literal: val}, nil
	}
}

// CheckSpecs refuses no fields, too many, duplicate keys and more than one
// stdin field.
func CheckSpecs(specs []FieldSpec) error {
	if len(specs) == 0 {
		return errors.New("at least one -field is required")
	}
	if len(specs) > maxFields {
		return fmt.Errorf("at most %d fields are allowed", maxFields)
	}
	seen := make(map[string]struct{}, len(specs))
	stdin := 0
	for _, f := range specs {
		if _, dup := seen[f.Key]; dup {
			return fmt.Errorf("field %q is given twice", f.Key)
		}
		seen[f.Key] = struct{}{}
		if f.Source == SourceStdin {
			stdin++
		}
	}
	if stdin > 1 {
		return errors.New("only one field may read its value from stdin (key=-)")
	}
	return nil
}
