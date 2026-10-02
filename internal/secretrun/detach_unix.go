// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretrun

import (
	"os/exec"
	"syscall"
)

// detach puts the opener in its own session so a Ctrl-C meant for the
// command doesn't also kill the browser it started.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
