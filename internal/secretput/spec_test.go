// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretput

import (
	"strings"
	"testing"
)

func TestParseFieldForms(t *testing.T) {
	cases := map[string]FieldSpec{
		"password=@/run/pw.txt": {Key: "password", Source: SourceFile, Path: "/run/pw.txt"},
		"password=-":            {Key: "password", Source: SourceStdin},
		"username=svc-backup":   {Key: "username", Source: SourceLiteral, Literal: "svc-backup"},
		"url=https://x/?a=b":    {Key: "url", Source: SourceLiteral, Literal: "https://x/?a=b"},
		"description=":          {Key: "description", Source: SourceLiteral},
	}
	for in, want := range cases {
		got, err := ParseField(in)
		if err != nil || got != want {
			t.Errorf("%q: got %+v err=%v, want %+v", in, got, err, want)
		}
	}
}

func TestParseFieldRefusesMalformedSpecs(t *testing.T) {
	for _, in := range []string{"", "password", "=value", "password=@", " =x", strings.Repeat("k", maxFieldKeyLen+1) + "=x"} {
		if _, err := ParseField(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseFieldErrorsNeverEchoALiteral(t *testing.T) {
	_, err := ParseField(strings.Repeat("k", maxFieldKeyLen+1) + "=LITERAL-MARKER")
	if err == nil || strings.Contains(err.Error(), "LITERAL-MARKER") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckSpecsAllowsOnlyOneStdinAndNoDuplicates(t *testing.T) {
	stdin := func(k string) FieldSpec { return FieldSpec{Key: k, Source: SourceStdin} }
	file := func(k string) FieldSpec { return FieldSpec{Key: k, Source: SourceFile, Path: "/p"} }
	if err := CheckSpecs([]FieldSpec{stdin("password"), file("passphrase")}); err != nil {
		t.Fatalf("one stdin: %v", err)
	}
	if err := CheckSpecs([]FieldSpec{stdin("password"), stdin("passphrase")}); err == nil || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("two stdin: err = %v", err)
	}
	if err := CheckSpecs([]FieldSpec{file("password"), file("password")}); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if err := CheckSpecs(nil); err == nil {
		t.Fatal("no fields accepted")
	}
	many := make([]FieldSpec, maxFields+1)
	for i := range many {
		many[i] = file("k" + strings.Repeat("x", i))
	}
	if err := CheckSpecs(many); err == nil {
		t.Fatal("too many fields accepted")
	}
}
