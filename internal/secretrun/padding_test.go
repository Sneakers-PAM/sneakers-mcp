// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

// deliveredBytes runs a child that copies what it was given into a capture
// file, so the masker on stdout never sees it.
func deliveredBytes(t *testing.T, value string, inject Inject, script string) string {
	t.Helper()
	capture := filepath.Join(t.TempDir(), "got")
	gw := &fakeGateway{states: []string{"APPROVED"}, value: value}
	o, _, errb := opts("sh", "-c", script, "sh", capture, FilePlaceholder)
	o.Inject = inject
	if code, err := Run(context.Background(), gw, o); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%q", code, err, errb.String())
	}
	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunDeliversPaddedValueOnStdinWithOneAppendedNewline(t *testing.T) {
	for _, v := range paddedValues {
		if got := deliveredBytes(t, v, InjectStdin, `cat > "$1"`); got != v+"\n" {
			t.Fatalf("stdin got %q, want %q", got, v+"\n")
		}
	}
}

func TestRunDeliversPaddedValueInTheFileExactly(t *testing.T) {
	for _, v := range paddedValues {
		if got := deliveredBytes(t, v, InjectFile, `cat "$2" > "$1"`); got != v {
			t.Fatalf("file got %q, want %q", got, v)
		}
	}
}
