// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseKeepFolderIsForACreateOnly(t *testing.T) {
	c, err := parse([]string{"-folder", "f1", "-type", "t", "-name", "n", "-keep-folder", "-field", "a=-"}, env(goodEnv))
	if err != nil || !c.req.KeepFolder {
		t.Fatalf("create: req=%+v err=%v", c.req, err)
	}
	if _, err := parse([]string{"-id", "s1", "-keep-folder", "-field", "a=-"}, env(goodEnv)); err == nil || !strings.Contains(err.Error(), "-keep-folder") {
		t.Fatalf("update with -keep-folder: err=%v", err)
	}
}

func TestRunCreatePrintsWhereTheSecretWentAndWhy(t *testing.T) {
	srv := fakeGateway(t, map[string]string{
		"createSecretForPrincipal": `{"data":{"createSecretForPrincipal":{"id":"s1","name":"lab vpn","folderId":"f-mine","typeId":"t",` +
			`"placement":{"folderId":"f-mine","requestedFolderId":"f1","rule":"PERSONAL_DEFAULT","reason":"the secret's name matches your username"}}}}`,
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"-insecure-localhost", "-folder", "f1", "-type", "t", "-name", "lab vpn", "-field", "password=-"},
		localEnv(srv.URL), strings.NewReader("STDIN-MARKER"), &stdout, &stderr)
	want := "id: s1\nname: lab vpn\nfolder: f-mine\nplacement: PERSONAL_DEFAULT: the secret's name matches your username\n"
	if code != 0 || stdout.String() != want {
		t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
