// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
)

const updateFieldsMutation = `mutation UpdateFields($id:ID!,$fields:[SecretFieldInput!]!){
  updateSecretFieldsForPrincipal(id:$id,fields:$fields){ secret{` + summaryFields + `} changedFieldKeys }
}`

// UpdateSecretFields sets the given fields of an existing secret. It returns
// the summary and the keys whose value changed, never values.
func (c *Client) UpdateSecretFields(ctx context.Context, token, id string, fields []Field) (*SecretSummary, []string, error) {
	var out struct {
		Updated *struct {
			Secret  *SecretSummary `json:"secret"`
			Changed []string       `json:"changedFieldKeys"`
		} `json:"updateSecretFieldsForPrincipal"`
	}
	if err := c.do(ctx, token, updateFieldsMutation, map[string]any{"id": id, "fields": fieldsOrEmpty(fields)}, &out); err != nil {
		return nil, nil, err
	}
	if out.Updated == nil || out.Updated.Secret == nil {
		return nil, nil, errors.New("gateway returned no secret")
	}
	keys := out.Updated.Changed
	if keys == nil {
		keys = []string{}
	}
	return out.Updated.Secret, keys, nil
}
