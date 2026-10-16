// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolRotate  = "sneakers_rotate_secret"
	toolRestore = "sneakers_restore_secret_version"
)

// --- sneakers_rotate_secret -------------------------------------------

type rotateSecretIn struct {
	SecretID string `json:"secretId"`
	PolicyID string `json:"policyId,omitempty" jsonschema:"optional password policy id override; else the field's own or the instance default"`
}
type rotateSecretOut struct {
	Secret   secretSummary `json:"secret"`
	NewValue string        `json:"newValue" jsonschema:"the freshly generated value, store it then set it on the target yourself"`
}

func (t *toolset) rotateSecret(ctx context.Context, req *mcp.CallToolRequest, in rotateSecretIn) (*mcp.CallToolResult, rotateSecretOut, error) {
	var out rotateSecretOut
	err := t.run(req, toolRotate,
		func() error {
			return checkAll(checkLen("secretId", in.SecretID, maxIDLen, true), checkLen("policyId", in.PolicyID, maxIDLen, false))
		},
		func(token string) error {
			s, val, err := t.gw.RotateSecret(ctx, token, in.SecretID, in.PolicyID)
			out = rotateSecretOut{Secret: summaryOf(s), NewValue: val}
			return err
		})
	if err != nil {
		return nil, rotateSecretOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_restore_secret_version -----------------------------------

type restoreSecretVersionIn struct {
	SecretID  string `json:"secretId"`
	VersionNo int    `json:"versionNo" jsonschema:"the version number to make current again, from sneakers_get_secret's history"`
}
type restoreSecretVersionOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) restoreSecretVersion(ctx context.Context, req *mcp.CallToolRequest, in restoreSecretVersionIn) (*mcp.CallToolResult, restoreSecretVersionOut, error) {
	var out restoreSecretVersionOut
	err := t.run(req, toolRestore,
		func() error {
			if in.VersionNo < 1 {
				return errors.New("versionNo must be at least 1")
			}
			return checkLen("secretId", in.SecretID, maxIDLen, true)
		},
		func(token string) error {
			s, err := t.gw.RestoreSecretVersion(ctx, token, in.SecretID, in.VersionNo)
			out.Secret = summaryOf(s)
			return err
		})
	if err != nil {
		return nil, restoreSecretVersionOut{}, err
	}
	return nil, out, nil
}

func registerRotateTools(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolRotate,
		Description: "Regenerate a secret's password field under its policy and store it as a new version. You need Author " +
			"(the same grant sneakers_create_secret needs), never just read. The new value is always returned: store it, then " +
			"set it on the target yourself, and sneakers_restore_secret_version it back if that fails. Refused while a scheduled " +
			"rotation of the secret is already queued or running.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, t.rotateSecret)
	mcp.AddTool(s, &mcp.Tool{
		Name: toolRestore,
		Description: "Make an earlier version of a secret current again, as a new version (never a history rewrite). You need " +
			"Author on the secret. Refused while a scheduled rotation is queued or running.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, t.restoreSecretVersion)
}
