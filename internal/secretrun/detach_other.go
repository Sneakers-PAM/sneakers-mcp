// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package secretrun

import "os/exec"

func detach(*exec.Cmd) {}
