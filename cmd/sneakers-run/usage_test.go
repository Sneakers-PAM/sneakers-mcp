// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"regexp"
	"strings"
	"testing"
)

func TestHelpPrintsFullUsageAndExitsZero(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{arg}, env(nil), &stdout, &stderr)
		if code != 0 || stdout.String() != usageText || stderr.Len() != 0 {
			t.Fatalf("%s: exit %d stdout=%q stderr=%q", arg, code, stdout.String(), stderr.String())
		}
	}
}

func TestUsageErrorPrintsTheErrorAndFullUsageAndExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-no-such-flag"}, env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org"}), &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "sneakers-run: ") || !strings.HasSuffix(stderr.String(), usageText) {
		t.Fatalf("exit %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestUsageDescribesEveryFlagAndTheEnvironment(t *testing.T) {
	fs, _ := newFlags()
	fs.VisitAll(func(f *flag.Flag) {
		if !regexp.MustCompile(`(?m)^\s+-` + regexp.QuoteMeta(f.Name) + `\b.*\S`).MatchString(usageText) {
			t.Errorf("usage does not describe -%s", f.Name)
		}
	})
	for _, want := range []string{
		"{secret_file}", "stdin", "file", "--",
		"SNEAKERS_URL", "SNEAKERS_TOKEN", "BROWSER",
		"sneakers-run -secret", "sneakers-run -inject file",
	} {
		if !strings.Contains(usageText, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

func TestUsageNamesNoRealHosts(t *testing.T) {
	lower := strings.ToLower(usageText)
	for _, m := range regexp.MustCompile(`[a-z]+://([^/\s:]+)`).FindAllStringSubmatch(lower, -1) {
		if host := m[1]; host != "localhost" && !strings.HasSuffix(host, "example.org") {
			t.Errorf("usage names host %q", host)
		}
	}
}
