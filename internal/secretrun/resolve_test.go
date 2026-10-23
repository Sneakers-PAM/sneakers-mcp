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

// trustedHasher returns a SHA-256 command whose program is on TrustedPath:
// sha256sum where it is (Linux), shasum -a 256 otherwise (macOS keeps
// sha256sum in /sbin, outside TrustedPath).
func trustedHasher(t *testing.T) []string {
	t.Helper()
	for _, argv := range [][]string{{"sha256sum"}, {"shasum", "-a", "256"}} {
		if _, err := resolveProgram(argv[0]); err == nil {
			return argv
		}
	}
	t.Fatalf("neither sha256sum nor shasum is in %v", TrustedPath)
	return nil
}

func TestRunIgnoresAShadowBinaryEarlierOnTheCallersPath(t *testing.T) {
	argv := trustedHasher(t)
	shadow := t.TempDir()
	marker := filepath.Join(t.TempDir(), "leaked")
	script := "#!/bin/sh\ncat > " + marker + "\n"
	if err := os.WriteFile(filepath.Join(shadow, argv[0]), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shadow+string(os.PathListSeparator)+os.Getenv("PATH"))

	gw := &fakeGateway{states: []string{"APPROVED"}, value: "hunter2"}
	o, out, errb := opts(argv...)
	code, err := Run(context.Background(), gw, o)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v stderr=%q", code, err, errb.String())
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("the shadow %s on $PATH received the secret", argv[0])
	}
	if !strings.Contains(out.String(), "  -") {
		t.Fatalf("trusted %s did not run: stdout=%q", argv[0], out.String())
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
