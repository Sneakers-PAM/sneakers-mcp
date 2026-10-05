// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestParseTakesTheRunIDFromTheFlagOrTheEnvironment(t *testing.T) {
	base := map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org"}
	withEnv := map[string]string{"SNEAKERS_RUN_ID": "run_env"}
	for k, v := range base {
		withEnv[k] = v
	}
	cases := []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"--run-id", "run_flag", "-secret", "s1", "--", "true"}, base, "run_flag"},
		{[]string{"-secret", "s1", "--", "true"}, withEnv, "run_env"},
		{[]string{"-run-id", "run_flag", "-secret", "s1", "--", "true"}, withEnv, "run_flag"},
		{[]string{"-secret", "s1", "--", "true"}, base, ""},
	}
	for _, tc := range cases {
		c, err := parse(tc.args, env(tc.env))
		if err != nil || c.opts.RunID != tc.want {
			t.Errorf("%v: run id %q err %v, want %q", tc.args, c.opts.RunID, err, tc.want)
		}
	}
}

func TestParseTakesThePurpose(t *testing.T) {
	c, err := parse([]string{"--purpose", "renew the lab cert", "-secret", "s1", "--", "true"},
		env(map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org"}))
	if err != nil || c.opts.Purpose != "renew the lab cert" {
		t.Fatalf("purpose %q err %v", c.opts.Purpose, err)
	}
}

func TestParseRefusesAMalformedRunID(t *testing.T) {
	base := map[string]string{"SNEAKERS_TOKEN": "snk_u_x", "SNEAKERS_URL": "https://sneakers.example.org"}
	if _, err := parse([]string{"--run-id", "run id", "-secret", "s1", "--", "true"}, env(base)); err == nil {
		t.Error("flag: want an error")
	}
	base["SNEAKERS_RUN_ID"] = "run/1"
	if _, err := parse([]string{"-secret", "s1", "--", "true"}, env(base)); err == nil {
		t.Error("env: want an error")
	}
}
