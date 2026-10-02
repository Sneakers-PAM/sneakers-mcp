// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func lookPathIn(found ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(found, name) {
			if filepath.IsAbs(name) {
				return name, nil
			}
			return "/opt/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func TestFindOpenerPrefersTheFirstBrowserEntryThatExists(t *testing.T) {
	cases := []struct {
		name    string
		browser string
		found   []string
		want    []string
	}{
		{"browser with args", "firefox --new-window", []string{"firefox", "xdg-open"}, []string{"/opt/bin/firefox", "--new-window"}},
		{"first existing entry", "missing:/usr/local/bin/chromium --incognito:firefox", []string{"/usr/local/bin/chromium", "firefox"}, []string{"/usr/local/bin/chromium", "--incognito"}},
		{"no browser entry exists", "missing", []string{"xdg-open"}, []string{"/opt/bin/xdg-open"}},
		{"xdg-open before open", "", []string{"open", "xdg-open"}, []string{"/opt/bin/xdg-open"}},
		{"macOS open", "", []string{"open"}, []string{"/opt/bin/open"}},
		{"nothing available", "", nil, nil},
	}
	for _, tc := range cases {
		getenv := func(k string) string {
			if k == "BROWSER" {
				return tc.browser
			}
			return ""
		}
		if got := FindOpener(getenv, lookPathIn(tc.found...)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOpenerArgvPutsTheURLAtThePlaceholderOrAtTheEnd(t *testing.T) {
	const u = "https://sneakers.example.org/approvals"
	if got := openerArgv([]string{"/opt/bin/xdg-open"}, u); !slices.Equal(got, []string{"/opt/bin/xdg-open", u}) {
		t.Errorf("appended: %q", got)
	}
	if got := openerArgv([]string{"/opt/bin/b", "--url=%s", "-x"}, u); !slices.Equal(got, []string{"/opt/bin/b", "--url=" + u, "-x"}) {
		t.Errorf("placeholder: %q", got)
	}
}

func TestStartOpenerIsNilWithoutAnOpener(t *testing.T) {
	if StartOpener(nil) != nil {
		t.Fatal("no opener must mean no Open func")
	}
}

func TestStartOpenerRunsDetachedWithoutTheToken(t *testing.T) {
	t.Setenv(TokenEnv, "snk_u_x")
	dir := t.TempDir()
	out := filepath.Join(dir, "env")
	open := StartOpener([]string{"/bin/sh", "-c", `{ env; echo "URL=$1"; } > "$0.tmp" && mv "$0.tmp" "$0"; echo noise; echo noise >&2`, out})
	open("https://sneakers.example.org/approvals")

	var b []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var err error
		if b, err = os.ReadFile(out); err == nil {
			break
		}
	}
	got := string(b)
	if !strings.Contains(got, "URL=https://sneakers.example.org/approvals\n") {
		t.Fatalf("opener did not get the URL: %q", got)
	}
	if strings.Contains(got, TokenEnv+"=") {
		t.Fatal("the token reached the opener's environment")
	}
}
