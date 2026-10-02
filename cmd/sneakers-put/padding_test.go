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
	"sync"
	"testing"
)

// recordingGateway answers createSecretForPrincipal and keeps the value sent
// for the "password" field.
func recordingGateway(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Variables struct {
				Fields []struct{ Key, Value string } `json:"fields"`
			} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		for _, f := range req.Variables.Fields {
			if f.Key == "password" {
				sent = f.Value
			}
		}
		mu.Unlock()
		_, _ = io.WriteString(w, `{"data":{"createSecretForPrincipal":{"id":"s1","name":"svc","folderId":"f1","typeId":"t"}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { mu.Lock(); defer mu.Unlock(); return sent }
}

func TestRunStoresPaddedValuesExactly(t *testing.T) {
	cases := []struct {
		name, content, want string
		stdin               bool
	}{
		{"file with newline", "abc==\n", "abc==", false},
		{"file without newline", "abc==", "abc==", false},
		{"stdin with newline", "abc==\n", "abc==", true},
		{"stdin without newline", "abc==", "abc==", true},
		{"file with embedded newline", "x=\n=", "x=\n=", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, sent := recordingGateway(t)
			field, stdin := "password=-", tc.content
			if !tc.stdin {
				p := filepath.Join(t.TempDir(), "pw")
				if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
				field, stdin = "password=@"+p, ""
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{"-insecure-localhost", "-folder", "f1", "-type", "t", "-name", "svc", "-field", field},
				localEnv(srv.URL), strings.NewReader(stdin), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit %d, stderr=%s", code, stderr.String())
			}
			if got := sent(); got != tc.want {
				t.Fatalf("stored %q, want %q", got, tc.want)
			}
		})
	}
}
