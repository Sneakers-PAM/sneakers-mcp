// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunIgnoresAShadowBinaryEarlierOnTheCallersPath(t *testing.T) {
	shadow := t.TempDir()
	marker := filepath.Join(t.TempDir(), "leaked")
	script := "#!/bin/sh\ncat > " + marker + "\n"
	if err := os.WriteFile(filepath.Join(shadow, "sha256sum"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shadow+string(os.PathListSeparator)+os.Getenv("PATH"))

	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, out, errb := opts("sha256sum")
	code, err := Run(context.Background(), gw, o)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%q", code, err, errb.String())
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("the shadow sha256sum on $PATH received the secret")
	}
	if !strings.Contains(out.String(), "  -") {
		t.Fatalf("trusted sha256sum did not run: stdout=%q", out.String())
	}
}

func TestRunRefusesABareNameOutsideTheTrustedPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only-here"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, _, _ := opts("only-here")
	if _, err := Run(context.Background(), gw, o); !errors.Is(err, ErrUntrustedProgram) || gw.prepared != nil {
		t.Fatalf("err=%v prepared=%v", err, gw.prepared)
	}
}

func TestRunRefusesARelativeProgramPath(t *testing.T) {
	for _, p := range []string{"./sha256sum", "bin/sha256sum"} {
		gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
		o, _, _ := opts(p)
		if _, err := Run(context.Background(), gw, o); !errors.Is(err, ErrUntrustedProgram) || gw.prepared != nil {
			t.Fatalf("%s: err=%v prepared=%v", p, err, gw.prepared)
		}
	}
}

func TestRunAcceptsAnAbsoluteProgramPathAsGiven(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "tool")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\nread v; echo \"$0 $v\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, out, _ := opts(prog)
	if code, err := Run(context.Background(), gw, o); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if gw.prepared[3] != prog || out.String() != prog+" "+maskText+"\n" {
		t.Fatalf("prepared=%v stdout=%q", gw.prepared, out.String())
	}
}

func TestRunRefusesAnAbsolutePathThatIsNotAnExecutableFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, plain, filepath.Join(dir, "missing")} {
		gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
		o, _, _ := opts(p)
		if _, err := Run(context.Background(), gw, o); !errors.Is(err, ErrUntrustedProgram) || gw.prepared != nil {
			t.Fatalf("%s: err=%v", p, err)
		}
	}
}
