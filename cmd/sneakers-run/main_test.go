// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/secretrun"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseTakesTheCommandAfterTheSeparator(t *testing.T) {
	c, err := parse([]string{"-secret", "s1", "-inject", "file", "--", "ssh", "-i", "{secret_file}", "admin@router-01"},
		env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint != "https://sneakers.example.org/machine/graphql" || c.opts.Token != "snk_u_x" || c.opts.SecretID != "s1" ||
		c.opts.FieldKey != "password" || c.opts.Inject != secretrun.InjectFile || strings.Join(c.opts.Argv, " ") != "ssh -i {secret_file} admin@router-01" {
		t.Fatalf("got %+v endpoint=%q", c.opts, c.endpoint)
	}
}

func TestParseRefusesMissingInputs(t *testing.T) {
	full := map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org"}
	cases := map[string]struct {
		args []string
		env  map[string]string
	}{
		"no token":       {[]string{"-secret", "s1", "--", "true"}, map[string]string{"SNEAKERS_URL": "https://x"}},
		"no url":         {[]string{"-secret", "s1", "--", "true"}, map[string]string{"SNEAKERS_TOKEN": "snk_u_x"}},
		"no secret":      {[]string{"--", "true"}, full},
		"no command":     {[]string{"-secret", "s1"}, full},
		"bad inject":     {[]string{"-secret", "s1", "-inject", "env", "--", "true"}, full},
		"not a personal": {[]string{"-secret", "s1", "--", "true"}, map[string]string{"SNEAKERS_TOKEN": "snk_sa_x", "SNEAKERS_URL": "https://x"}},
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
		{"ftp://sneakers.example.org", nil, false},
		{"sneakers.example.org", nil, false},
	}
	for _, tc := range cases {
		args := append(append([]string{}, tc.flags...), "-secret", "s1", "--", "true")
		_, err := parse(args, env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": tc.url}))
		if (err == nil) != tc.ok {
			t.Errorf("%s %v: err=%v, want ok=%v", tc.url, tc.flags, err, tc.ok)
		}
	}
}

func TestNoOpenTurnsTheBrowserOff(t *testing.T) {
	e := env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org", "BROWSER": "firefox"})
	found := func(name string) (string, error) { return "/opt/bin/" + name, nil }

	c, err := parse([]string{"-no-open", "-secret", "s1", "--", "true"}, e)
	if err != nil {
		t.Fatal(err)
	}
	if opener(c, e, found) != nil {
		t.Fatal("-no-open must not open a browser")
	}

	c, err = parse([]string{"-secret", "s1", "--", "true"}, e)
	if err != nil {
		t.Fatal(err)
	}
	if opener(c, e, found) == nil {
		t.Fatal("without -no-open an available browser must be used")
	}
}
