// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretput

import (
	"context"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

const createReply = `{"data":{"createSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f1","typeId":"type-password"}}}`

func putOne(t *testing.T, spec FieldSpec, stdin string) string {
	t.Helper()
	gw := newFake(t, map[string]string{"createSecretForPrincipal": createReply})
	if _, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
		Token: "snk_u_x", FolderID: "f1", TypeID: "type-password", Name: "svc",
		Fields: []FieldSpec{spec}, Stdin: strings.NewReader(stdin),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	return gw.fields("createSecretForPrincipal")[spec.Key]
}

func TestFileValueKeepsPaddingAndDropsOnlyOneTrailingNewline(t *testing.T) {
	for _, v := range paddedValues {
		for _, content := range []string{v, v + "\n", v + "\r\n"} {
			got := putOne(t, FieldSpec{Key: "password", Source: SourceFile, Path: writeFile(t, content)}, "")
			if got != v {
				t.Fatalf("file %q stored %q, want %q", content, got, v)
			}
		}
	}
}

func TestStdinValueKeepsPaddingAndDropsOnlyOneTrailingNewline(t *testing.T) {
	for _, v := range paddedValues {
		for _, content := range []string{v, v + "\n", v + "\r\n"} {
			got := putOne(t, FieldSpec{Key: "password", Source: SourceStdin}, content)
			if got != v {
				t.Fatalf("stdin %q stored %q, want %q", content, got, v)
			}
		}
	}
}

func TestUpdateFromFileKeepsPadding(t *testing.T) {
	for _, v := range paddedValues {
		gw := newFake(t, map[string]string{
			"updateSecretFieldsForPrincipal": `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f1","typeId":"type-password"},"changedFieldKeys":["password"]}}}`,
		})
		if _, err := Put(context.Background(), gwclient.New(gw.URL, nil), Request{
			Token: "snk_u_x", SecretID: "s1",
			Fields: []FieldSpec{{Key: "password", Source: SourceFile, Path: writeFile(t, v+"\n")}},
		}); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if got := gw.fields("updateSecretFieldsForPrincipal")["password"]; got != v {
			t.Fatalf("stored %q, want %q", got, v)
		}
	}
}

func TestParseFieldSplitsOnlyOnTheFirstEquals(t *testing.T) {
	for _, v := range []string{"abc=", "abc==", "YWJjZA=="} {
		spec, err := ParseField("username=" + v)
		if err != nil || spec.Key != "username" || spec.Source != SourceLiteral || spec.Literal != v {
			t.Fatalf("ParseField(%q) = %+v, %v", "username="+v, spec, err)
		}
	}
	spec, err := ParseField("password=@/tmp/abc==")
	if err != nil || spec.Source != SourceFile || spec.Path != "/tmp/abc==" {
		t.Fatalf("file spec = %+v, %v", spec, err)
	}
}
