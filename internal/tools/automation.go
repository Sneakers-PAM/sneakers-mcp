// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const toolSetAutomation = "sneakers_set_secret_automation"

// neverRotateHint is shared by the create and generate descriptions: a
// rotating type on a credential that must stay fixed can lock people out.
const neverRotateHint = "Credentials that must never rotate (for example a DSRM password) " +
	"must be created with disableRotation: true, so no rotation is ever scheduled. Use " + toolSetAutomation +
	" to change it later."

type setSecretAutomationIn struct {
	ID               string `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	DisableRotation  bool   `json:"disableRotation" jsonschema:"true turns rotation off; false turns it back on"`
	DisableHeartbeat bool   `json:"disableHeartbeat" jsonschema:"true turns heartbeat checks off; false turns them back on"`
}
type setSecretAutomationOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) setSecretAutomation(ctx context.Context, req *mcp.CallToolRequest, in setSecretAutomationIn) (*mcp.CallToolResult, setSecretAutomationOut, error) {
	var out setSecretAutomationOut
	err := t.run(req, toolSetAutomation,
		func() error { return checkLen("id", in.ID, maxIDLen, true) },
		func(token string) error {
			s, err := t.gw.SetSecretAutomation(ctx, token, in.ID, in.DisableRotation, in.DisableHeartbeat)
			if err == nil {
				out.Secret = summaryOf(s)
			}
			return err
		})
	if err != nil {
		return nil, setSecretAutomationOut{}, err
	}
	return nil, out, nil
}

func registerAutomationTool(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolSetAutomation,
		Description: "Turn rotation and heartbeat checks off or back on for one secret. Both flags are set on every " +
			"call, so pass the current value (rotationOptOut/heartbeatOptOut from sneakers_find_secrets) for the one " +
			"you are not changing. Turning rotation off removes the secret's rotation schedule. Requires the same " +
			"access as the UI. Audited.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.setSecretAutomation)
}
