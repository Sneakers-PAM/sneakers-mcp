// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestMaskerHidesTheValueAndItsEncodings(t *testing.T) {
	const v = "p@ss word/+1"
	var out bytes.Buffer
	m := newMasker(&out, v)
	in := strings.Join([]string{
		"plain " + v,
		"b64 " + base64.StdEncoding.EncodeToString([]byte(v)),
		"b64raw " + base64.RawStdEncoding.EncodeToString([]byte(v)),
		"b64url " + base64.URLEncoding.EncodeToString([]byte(v)),
		"hex " + hex.EncodeToString([]byte(v)),
		"HEX " + strings.ToUpper(hex.EncodeToString([]byte(v))),
		"query " + url.QueryEscape(v),
		"path " + url.PathEscape(v),
	}, "\n")
	if _, err := m.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Count(got, maskText) != 8 || strings.Contains(got, "word") {
		t.Fatalf("masked output leaks: %q", got)
	}
}

func TestMaskerCatchesAValueSplitAcrossWrites(t *testing.T) {
	var out bytes.Buffer
	m := newMasker(&out, "hunter2")
	for _, c := range []string{"login: hun", "te", "r2 ok\n"} {
		_, _ = m.Write([]byte(c))
	}
	_ = m.Close()
	if out.String() != "login: "+maskText+" ok\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestMaskerPassesOtherOutputThroughUnchanged(t *testing.T) {
	var out bytes.Buffer
	m := newMasker(&out, "hunter2")
	_, _ = m.Write([]byte("nothing secret here\n"))
	_ = m.Close()
	if out.String() != "nothing secret here\n" {
		t.Fatalf("got %q", out.String())
	}
}
