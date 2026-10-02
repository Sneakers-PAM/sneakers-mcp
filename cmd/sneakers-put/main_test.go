// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/secretput"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var goodEnv = map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org/"}

func TestParseCreateMode(t *testing.T) {
	c, err := parse([]string{"-folder", "f1", "-type", "type-password", "-name", "recovery-admin", "-disable-rotation",
		"-field", "password=@/run/pw", "-field", "username=Administrator"}, env(goodEnv))
	if err != nil {
		t.Fatal(err)
	}
	r := c.req
	if c.endpoint != "https://sneakers.example.org/machine/graphql" || r.Token != "snk_u_x" || r.FolderID != "f1" ||
		r.TypeID != "type-password" || r.Name != "recovery-admin" || !r.DisableRotation || r.SecretID != "" || len(r.Fields) != 2 ||
		r.Fields[0] != (secretput.FieldSpec{Key: "password", Source: secretput.SourceFile, Path: "/run/pw"}) {
		t.Fatalf("got %+v endpoint=%q", r, c.endpoint)
	}
}

func TestParseUpdateMode(t *testing.T) {
	c, err := parse([]string{"-id", "s1", "-field", "password=-"}, env(goodEnv))
	if err != nil {
		t.Fatal(err)
	}
	if c.req.SecretID != "s1" || c.req.FolderID != "" || len(c.req.Fields) != 1 || c.req.Fields[0].Source != secretput.SourceStdin {
		t.Fatalf("got %+v", c.req)
	}
}

func TestParseRefusesBadInput(t *testing.T) {
	create := []string{"-folder", "f", "-type", "t", "-name", "n"}
	with := func(extra ...string) []string { return append(append([]string{}, create...), extra...) }
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"no token":             {with("-field", "a=-"), map[string]string{"SNEAKERS_URL": "https://x"}},
		"service token":        {with("-field", "a=-"), map[string]string{"SNEAKERS_TOKEN": "snk_sa_x", "SNEAKERS_URL": "https://x"}},
		"no url":               {with("-field", "a=-"), map[string]string{"SNEAKERS_TOKEN": "snk_u_x"}},
		"no fields":            {with(), goodEnv},
		"two stdin":            {with("-field", "a=-", "-field", "b=-"), goodEnv},
		"duplicate key":        {with("-field", "a=@/x", "-field", "a=@/y"), goodEnv},
		"malformed field":      {with("-field", "novalue"), goodEnv},
		"empty file":           {with("-field", "a=@"), goodEnv},
		"no mode":              {[]string{"-field", "a=-"}, goodEnv},
		"create missing name":  {[]string{"-folder", "f", "-type", "t", "-field", "a=-"}, goodEnv},
		"create missing type":  {[]string{"-folder", "f", "-name", "n", "-field", "a=-"}, goodEnv},
		"both modes":           {with("-id", "s1", "-field", "a=-"), goodEnv},
		"update with rotation": {[]string{"-id", "s1", "-disable-rotation", "-field", "a=-"}, goodEnv},
		"update with name":     {[]string{"-id", "s1", "-name", "n", "-field", "a=-"}, goodEnv},
		"positional args":      {with("-field", "a=-", "extra"), goodEnv},
		"unknown flag":         {with("-value", "x"), goodEnv},
	}
	for name, tc := range cases {
		if _, err := parse(tc.args, env(tc.env)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseRequiresHTTPSUnlessExplicitlyLocal(t *testing.T) {
	cases := []struct {
		url   string
		flags []string
		ok    bool
	}{
		{"https://sneakers.example.org", nil, true},
		{"http://sneakers.example.org", nil, false},
		{"http://localhost:9100", nil, false},
		{"http://localhost:9100", []string{"-insecure-localhost"}, true},
		{"http://127.0.0.1:9100", []string{"-insecure-localhost"}, true},
		{"http://[::1]:9100", []string{"-insecure-localhost"}, true},
		{"http://sneakers.example.org", []string{"-insecure-localhost"}, false},
		{"http://localhost.example.org", []string{"-insecure-localhost"}, false},
		{"sneakers.example.org", nil, false},
	}
	for _, tc := range cases {
		args := append(append([]string{}, tc.flags...), "-id", "s1", "-field", "password=-")
		_, err := parse(args, env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": tc.url}))
		if (err == nil) != tc.ok {
			t.Errorf("%s %v: err=%v, want ok=%v", tc.url, tc.flags, err, tc.ok)
		}
	}
}

func fakeGateway(t *testing.T, replies map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		for op, body := range replies {
			if strings.Contains(req.Query, op) {
				_, _ = io.WriteString(w, body)
				return
			}
		}
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func localEnv(url string) func(string) string {
	return env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": url})
}

func TestRunCreatePrintsOnlyIDAndName(t *testing.T) {
	srv := fakeGateway(t, map[string]string{
		"createSecretForPrincipal": `{"data":{"createSecretForPrincipal":{"id":"s1","name":"recovery-admin","folderId":"f1","typeId":"t"}}}`,
	})
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("FILE-MARKER\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-insecure-localhost", "-folder", "f1", "-type", "t", "-name", "recovery-admin", "-field", "password=@" + pw, "-field", "passphrase=-"},
		localEnv(srv.URL), strings.NewReader("STDIN-MARKER"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, stderr.String())
	}
	if stdout.String() != "id: s1\nname: recovery-admin\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	for _, leak := range []string{"FILE-MARKER", "STDIN-MARKER", "snk_u_x"} {
		if strings.Contains(stdout.String()+stderr.String(), leak) {
			t.Fatalf("output leaks %s", leak)
		}
	}
}

func TestRunUpdatePrintsChangedKeys(t *testing.T) {
	srv := fakeGateway(t, map[string]string{
		"updateSecretFieldsForPrincipal": `{"data":{"updateSecretFieldsForPrincipal":{"secret":{"id":"s1","name":"svc","folderId":"f1","typeId":"t"},"changedFieldKeys":["password"]}}}`,
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"-insecure-localhost", "-id", "s1", "-field", "password=-"}, localEnv(srv.URL), strings.NewReader("STDIN-MARKER\n"), &stdout, &stderr)
	if code != 0 || stdout.String() != "id: s1\nname: svc\nchanged: password\n" {
		t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "STDIN-MARKER") {
		t.Fatal("output leaks the value")
	}
}

func TestRunFailureNeverPrintsValues(t *testing.T) {
	srv := fakeGateway(t, map[string]string{
		"updateSecretFieldsForPrincipal": `{"data":null,"errors":[{"message":"STDIN-MARKER is not allowed"}]}`,
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"-insecure-localhost", "-id", "s1", "-field", "password=-"}, localEnv(srv.URL), strings.NewReader("STDIN-MARKER"), &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "is not allowed") || strings.Contains(stderr.String(), "STDIN-MARKER") {
		t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunRefusesALiteralForASensitiveField(t *testing.T) {
	srv := fakeGateway(t, map[string]string{
		"secretTypes":              `{"data":{"secretTypes":[{"id":"t","name":"Password","fields":[{"key":"password","label":"Password","kind":"PASSWORD","required":true}]}]}}`,
		"createSecretForPrincipal": `{"data":{"createSecretForPrincipal":{"id":"s1","name":"n","folderId":"f1","typeId":"t"}}}`,
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"-insecure-localhost", "-folder", "f1", "-type", "t", "-name", "n", "-field", "password=LITERAL-MARKER"},
		localEnv(srv.URL), strings.NewReader(""), &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "password=@file") || strings.Contains(stderr.String(), "LITERAL-MARKER") {
		t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestParseErrorsNeverEchoAFieldArgument(t *testing.T) {
	_, err := parse([]string{"-id", "s1", "-field", "PASTED-VALUE-MARKER"}, env(goodEnv))
	if err == nil || strings.Contains(err.Error(), "PASTED-VALUE-MARKER") {
		t.Fatalf("err = %v", err)
	}
}
