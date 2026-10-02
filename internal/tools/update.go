// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const toolUpdate = "sneakers_update_secret"

const maxUpdateFields = 20

// --- sneakers_update_secret -----------------------------------------------

type updateSecretIn struct {
	ID     string    `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	Fields []fieldIn `json:"fields" jsonschema:"non-sensitive fields to set, e.g. url, endpoint, notes or description; keys must be declared by the secret's type"`
}
type updateSecretOut struct {
	Secret           secretSummary `json:"secret"`
	ChangedFieldKeys []string      `json:"changedFieldKeys"`
}

func checkUpdateFields(fields []fieldIn) error {
	if len(fields) == 0 {
		return errors.New("at least one field is required")
	}
	if len(fields) > maxUpdateFields {
		return fmt.Errorf("at most %d fields are allowed", maxUpdateFields)
	}
	return checkFields(fields)
}

func putHint(id, key string) string {
	return fmt.Sprintf("use sneakers-put for secret values: sneakers-put -id %s -field %s=@file", id, key)
}

// refuseUnsafeKeys is checked here and not left to vault, because vault would
// accept a sensitive value too, and by then it has already crossed the
// transcript.
func (t *toolset) refuseUnsafeKeys(ctx context.Context, token string, in updateSecretIn) error {
	found, err := t.gw.FindSecrets(ctx, token, "", "", "")
	if err != nil {
		return err
	}
	typeID := ""
	for _, s := range found {
		if s.ID == in.ID {
			typeID = s.TypeID
			break
		}
	}
	if typeID == "" {
		return fmt.Errorf("%w: secret %s is not visible to this token", errInvalidInput, in.ID)
	}
	types, err := t.gw.ListSecretTypes(ctx, token)
	if err != nil {
		return err
	}
	sensitive := map[string]bool{}
	known := false
	for _, ty := range types {
		if ty.ID != typeID {
			continue
		}
		known = true
		for _, f := range ty.Fields {
			sensitive[f.Key] = f.Sensitive
		}
	}
	if !known {
		return fmt.Errorf("%w: the type %s of secret %s is not in the type catalog", errInvalidInput, typeID, in.ID)
	}
	for _, f := range in.Fields {
		s, declared := sensitive[f.Key]
		switch {
		case !declared:
			return fmt.Errorf("%w: field %q is not declared by type %s, so it may hold a secret; %s",
				errInvalidInput, f.Key, typeID, putHint(in.ID, f.Key))
		case s:
			return fmt.Errorf("%w: field %q is sensitive in type %s and cannot be set through this tool; %s",
				errInvalidInput, f.Key, typeID, putHint(in.ID, f.Key))
		}
	}
	return nil
}

func (t *toolset) updateSecret(ctx context.Context, req *mcp.CallToolRequest, in updateSecretIn) (*mcp.CallToolResult, updateSecretOut, error) {
	var out updateSecretOut
	err := t.run(req, toolUpdate,
		func() error { return checkAll(checkLen("id", in.ID, maxIDLen, true), checkUpdateFields(in.Fields)) },
		func(token string) error {
			if err := t.refuseUnsafeKeys(ctx, token, in); err != nil {
				return err
			}
			s, keys, err := t.gw.UpdateSecretFields(ctx, token, in.ID, fieldsOf(in.Fields))
			if err == nil {
				out = updateSecretOut{Secret: summaryOf(*s), ChangedFieldKeys: keys}
			}
			return err
		})
	if err != nil {
		return nil, updateSecretOut{}, err
	}
	return nil, out, nil
}

func registerUpdateTool(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolUpdate,
		Description: "Set non-sensitive fields of one existing secret: a URL or endpoint, notes, a description and " +
			"similar. Each key must be declared by the secret's type and not marked sensitive (see " + toolTypes +
			"); anything else is refused before the vault is called. Secret values (passwords, keys, tokens) never " +
			"go through this tool: have the user run the local sneakers-put command " +
			"(sneakers-put -id <id> -field key=@file). Returns the secret summary and the keys whose value changed, " +
			"never values. Requires author access to the secret; the previous values stay in version history. The " +
			"call is audited as an update against the token's user or service account.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.updateSecret)
}
