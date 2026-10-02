// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRenameSecretSendsArgsAndDecodesSummary(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"renameSecretForPrincipal":{"id":"s1","name":"SSH router-01","folderId":"f","typeId":"t"}}}`, 200)

	s, err := New(srv.URL, nil).RenameSecret(context.Background(), "tok", "s1", "SSH router-01")
	if err != nil || s.ID != "s1" || s.Name != "SSH router-01" {
		t.Fatalf("s=%+v err=%v", s, err)
	}
	if cp.auth != "Bearer tok" || !strings.Contains(cp.query, "renameSecretForPrincipal") {
		t.Fatalf("auth=%q query=%q", cp.auth, cp.query)
	}
	if cp.vars["id"] != "s1" || cp.vars["name"] != "SSH router-01" {
		t.Fatalf("vars = %#v", cp.vars)
	}
}

func TestCreateFolderSendsArgsAndDecodesFolder(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"createFolderForPrincipal":{"id":"f9","name":"SSH Keys","parentId":"f1","path":"SSH Keys","canAuthor":true}}}`, 200)

	f, err := New(srv.URL, nil).CreateFolder(context.Background(), "tok", "f1", "SSH Keys")
	if err != nil || f.ID != "f9" || f.ParentID == nil || *f.ParentID != "f1" || f.Path != "SSH Keys" || !f.CanAuthor {
		t.Fatalf("f=%+v err=%v", f, err)
	}
	if !strings.Contains(cp.query, "createFolderForPrincipal") || cp.vars["parentId"] != "f1" || cp.vars["name"] != "SSH Keys" {
		t.Fatalf("query=%q vars=%#v", cp.query, cp.vars)
	}
}

func TestRenameFolderSendsArgsAndDecodesFolder(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":{"renameFolderForPrincipal":{"id":"f9","name":"Keys","parentId":"f1","path":"Keys","canAuthor":true}}}`, 200)

	f, err := New(srv.URL, nil).RenameFolder(context.Background(), "tok", "f9", "Keys")
	if err != nil || f.ID != "f9" || f.Name != "Keys" {
		t.Fatalf("f=%+v err=%v", f, err)
	}
	if !strings.Contains(cp.query, "renameFolderForPrincipal") || cp.vars["id"] != "f9" || cp.vars["name"] != "Keys" {
		t.Fatalf("query=%q vars=%#v", cp.query, cp.vars)
	}
}

func TestOrganizeDenialIsAGraphQLError(t *testing.T) {
	var cp capture
	srv := newFakeGateway(t, &cp, `{"data":null,"errors":[{"message":"not permitted to author in that folder"}]}`, 200)
	c := New(srv.URL, nil)
	var ge *GraphQLError
	if _, err := c.CreateFolder(context.Background(), "tok", "f1", "x"); !errors.As(err, &ge) {
		t.Fatalf("create folder: err = %v", err)
	}
	if _, err := c.RenameFolder(context.Background(), "tok", "f1", "x"); !errors.As(err, &ge) {
		t.Fatalf("rename folder: err = %v", err)
	}
	if _, err := c.RenameSecret(context.Background(), "tok", "s1", "x"); !errors.As(err, &ge) {
		t.Fatalf("rename secret: err = %v", err)
	}
}
