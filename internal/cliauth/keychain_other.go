// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package cliauth

func defaultStore() Store { return nil }
