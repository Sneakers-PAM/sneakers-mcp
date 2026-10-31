// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRenameSecretToolForwardsAndReturnsSummary(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"renameSecretForPrincipal":{"id":"s1","name":"SSH router-01","folderId":"f","typeId":"t"}}}`)

	_, out, err := newTools(gw.URL, nil).renameSecret(context.Background(), callReq("Bearer agent-tok"), renameSecretIn{ID: "s1", Name: "SSH router-01"})
	if err != nil || out.Secret.ID != "s1" || out.Secret.Name != "SSH router-01" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if gw.gotAuth() != "Bearer agent-tok" || vars["id"] != "s1" || vars["name"] != "SSH router-01" {
		t.Fatalf("auth=%q vars=%#v", gw.gotAuth(), vars)
	}
}

func TestCreateFolderToolForwardsAndReturnsFolder(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createFolderForPrincipal":{"id":"f9","name":"SSH Keys","parentId":"f1","path":"SSH Keys","canAuthor":true}}}`)

	_, out, err := newTools(gw.URL, nil).createFolder(context.Background(), callReq("Bearer t"), createFolderIn{ParentID: "f1", Name: "SSH Keys"})
	if err != nil || out.Folder.ID != "f9" || out.Folder.ParentID != "f1" || out.Folder.Path != "SSH Keys" || !out.Folder.CanAuthor {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if vars["parentId"] != "f1" || vars["name"] != "SSH Keys" {
		t.Fatalf("vars = %#v", vars)
	}
}

func TestCreateFolderToolWithNoParentCreatesTopLevel(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createFolderForPrincipal":{"id":"f9","name":"Infrastructure","parentId":null,"path":"Infrastructure","canAuthor":true}}}`)

	_, out, err := newTools(gw.URL, nil).createFolder(context.Background(), callReq("Bearer t"), createFolderIn{Name: "Infrastructure"})
	if err != nil || out.Folder.ID != "f9" || out.Folder.ParentID != "" || out.Folder.Path != "Infrastructure" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if _, sent := vars["parentId"]; sent || vars["name"] != "Infrastructure" {
		t.Fatalf("vars = %#v, want no parentId", vars)
	}
}

func TestCreateFolderToolExplainsTheTopLevelRestriction(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = PermissionDenied desc = refused",`+
		`"extensions":{"code":"PERMISSION_DENIED","reason":"TOP_LEVEL_FOLDERS_RESTRICTED","domain":"sneakers.vault"}}]}`)

	_, out, err := newTools(gw.URL, nil).createFolder(context.Background(), callReq("Bearer t"), createFolderIn{Name: "x"})
	if err == nil || out.Folder.ID != "" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	for _, want := range []string{"PERMISSION_DENIED", "TOP_LEVEL_FOLDERS_RESTRICTED", `"Restrict top-level folders to admins"`, "parentId"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "rpc error") {
		t.Errorf("error %q still carries the gRPC wrapper", err)
	}
}

func TestCreateFolderToolExplainsTheServiceAccountRefusal(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"rpc error: code = InvalidArgument desc = parent_id is required: a machine cannot create a top-level folder",`+
		`"extensions":{"code":"INVALID_ARGUMENT"}}]}`)

	_, _, err := newTools(gw.URL, nil).createFolder(context.Background(), callReq("Bearer t"), createFolderIn{Name: "x"})
	if err == nil {
		t.Fatal("want the refusal")
	}
	for _, want := range []string{"INVALID_ARGUMENT", "service account", "parentId"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// Any other INVALID_ARGUMENT, such as a bad name, keeps the vault's own words.
func TestCreateFolderToolRelaysOtherInvalidArguments(t *testing.T) {
	const msg = "rpc error: code = InvalidArgument desc = name contains control characters"
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"`+msg+`","extensions":{"code":"INVALID_ARGUMENT"}}]}`)

	_, _, err := newTools(gw.URL, nil).createFolder(context.Background(), callReq("Bearer t"), createFolderIn{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "name contains control characters") {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateFolderDescriptionStatesTheTopLevelRule(t *testing.T) {
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != toolCreateFolder {
			continue
		}
		for _, want := range []string{"top-level", "Restrict top-level folders to admins", "another user's Personal tree"} {
			if !strings.Contains(tl.Description, want) {
				t.Errorf("description lacks %q: %s", want, tl.Description)
			}
		}
		if strings.Contains(tl.Description, "never at the top level") {
			t.Errorf("description still rules out the top level: %s", tl.Description)
		}
		return
	}
	t.Fatal("tool not registered")
}

func TestRenameFolderToolForwardsAndReturnsFolder(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"renameFolderForPrincipal":{"id":"f9","name":"Keys","parentId":"f1","path":"Keys","canAuthor":true}}}`)

	_, out, err := newTools(gw.URL, nil).renameFolder(context.Background(), callReq("Bearer t"), renameFolderIn{ID: "f9", Name: "Keys"})
	if err != nil || out.Folder.ID != "f9" || out.Folder.Name != "Keys" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if vars["id"] != "f9" || vars["name"] != "Keys" {
		t.Fatalf("vars = %#v", vars)
	}
}

// No author right, a personal parent folder and a duplicate sibling name
// are all refused by vault and come back as GraphQL errors.
func TestOrganizeToolDenialsSurfaceAsToolErrors(t *testing.T) {
	for _, msg := range []string{
		"rpc error: code = PermissionDenied desc = not permitted to author in that folder",
		"rpc error: code = PermissionDenied desc = creating a folder inside a personal folder requires a human",
		"rpc error: code = AlreadyExists desc = a folder with that name already exists here",
	} {
		gw := fakeGateway(t, `{"data":null,"errors":[{"message":"`+msg+`"}]}`)
		ts := newTools(gw.URL, nil)
		want := msg[strings.Index(msg, "desc = ")+len("desc = "):]

		_, cout, err := ts.createFolder(context.Background(), callReq("Bearer t"), createFolderIn{ParentID: "f1", Name: "x"})
		if err == nil || !strings.Contains(err.Error(), want) || cout.Folder.ID != "" {
			t.Fatalf("create folder: err=%v out=%+v", err, cout)
		}
		_, fout, err := ts.renameFolder(context.Background(), callReq("Bearer t"), renameFolderIn{ID: "f1", Name: "x"})
		if err == nil || !strings.Contains(err.Error(), want) || fout.Folder.ID != "" {
			t.Fatalf("rename folder: err=%v out=%+v", err, fout)
		}
		_, sout, err := ts.renameSecret(context.Background(), callReq("Bearer t"), renameSecretIn{ID: "s1", Name: "x"})
		if err == nil || !strings.Contains(err.Error(), want) || sout.Secret.ID != "" {
			t.Fatalf("rename secret: err=%v out=%+v", err, sout)
		}
	}
}

func TestOrganizeToolsRefuseInvalidNamesBeforeCallingGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	ctx := context.Background()
	long := func(n int) string { return strings.Repeat("x", n) }
	renameS := func(in renameSecretIn) func() error {
		return func() error { _, _, err := ts.renameSecret(ctx, callReq("Bearer t"), in); return err }
	}
	createF := func(in createFolderIn) func() error {
		return func() error { _, _, err := ts.createFolder(ctx, callReq("Bearer t"), in); return err }
	}
	renameF := func(in renameFolderIn) func() error {
		return func() error { _, _, err := ts.renameFolder(ctx, callReq("Bearer t"), in); return err }
	}
	checks := map[string]func() error{
		"rename secret: id missing":      renameS(renameSecretIn{Name: "n"}),
		"rename secret: id too long":     renameS(renameSecretIn{ID: long(maxIDLen + 1), Name: "n"}),
		"rename secret: name empty":      renameS(renameSecretIn{ID: "s"}),
		"rename secret: name blank":      renameS(renameSecretIn{ID: "s", Name: "   "}),
		"rename secret: name too long":   renameS(renameSecretIn{ID: "s", Name: long(maxNameLen + 1)}),
		"rename secret: name with slash": renameS(renameSecretIn{ID: "s", Name: "a/b"}),
		"create folder: parent too long": createF(createFolderIn{ParentID: long(maxIDLen + 1), Name: "n"}),
		"create folder: name empty":      createF(createFolderIn{ParentID: "f"}),
		"create folder: name too long":   createF(createFolderIn{ParentID: "f", Name: long(maxNameLen + 1)}),
		"create folder: name with slash": createF(createFolderIn{ParentID: "f", Name: "Personal/SSH Keys"}),
		"rename folder: id missing":      renameF(renameFolderIn{Name: "n"}),
		"rename folder: name empty":      renameF(renameFolderIn{ID: "f"}),
		"rename folder: name too long":   renameF(renameFolderIn{ID: "f", Name: long(maxNameLen + 1)}),
		"rename folder: name with slash": renameF(renameFolderIn{ID: "f", Name: "/"}),
	}
	for name, fn := range checks {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times for invalid input", gw.calls.Load())
	}
}

func TestOrganizeToolsLogNeitherTokensNorNames(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"renameSecretForPrincipal":{"id":"s1","name":"NAME-MARKER","folderId":"f","typeId":"t"}}}`)
	var buf bytes.Buffer
	if _, _, err := newTools(gw.URL, &buf).renameSecret(context.Background(), callReq("Bearer TOKEN-MARKER"), renameSecretIn{ID: "s1", Name: "NAME-MARKER"}); err != nil {
		t.Fatal(err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "sneakers_rename_secret") {
		t.Fatalf("expected a log line for the tool, got: %s", logs)
	}
	for _, leak := range []string{"TOKEN-MARKER", "NAME-MARKER"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log output leaks %s: %s", leak, logs)
		}
	}
}
