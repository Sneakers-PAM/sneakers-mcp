// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secretrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUntrustedProgram means argv[0] is neither a program on the trusted PATH
// nor an absolute path to an executable file.
var ErrUntrustedProgram = errors.New("program must be a name on the trusted PATH or an absolute path to an executable")

// TrustedPath is where bare program names are looked up. The caller's $PATH is
// never used: a grant names a program, and anything earlier on a user-writable
// PATH could stand in for it and receive the value.
var TrustedPath = []string{"/usr/local/bin", "/usr/bin", "/bin"}

// resolveProgram returns the absolute file to execute for argv0.
func resolveProgram(argv0 string) (string, error) {
	if strings.Contains(argv0, "/") {
		if !filepath.IsAbs(argv0) {
			return "", fmt.Errorf("%w: %q is a relative path", ErrUntrustedProgram, argv0)
		}
		if !isExecutableFile(argv0) {
			return "", fmt.Errorf("%w: %q is not an executable file", ErrUntrustedProgram, argv0)
		}
		return argv0, nil
	}
	for _, dir := range TrustedPath {
		if p := filepath.Join(dir, argv0); isExecutableFile(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: %q is not in %s", ErrUntrustedProgram, argv0, strings.Join(TrustedPath, ":"))
}

func isExecutableFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
