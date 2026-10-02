// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import "context"

const setAutomationMutation = `mutation SetAutomation($secretId:ID!,$disableRotation:Boolean!,$disableHeartbeat:Boolean!){
  setSecretAutomationForPrincipal(secretId:$secretId,disableRotation:$disableRotation,disableHeartbeat:$disableHeartbeat){` + summaryFields + `}
}`

// SetSecretAutomation sets both of a secret's opt-outs. Disabling rotation
// also removes its rotation schedule.
func (c *Client) SetSecretAutomation(ctx context.Context, token, secretID string, disableRotation, disableHeartbeat bool) (SecretSummary, error) {
	var out struct {
		Secret SecretSummary `json:"setSecretAutomationForPrincipal"`
	}
	vars := map[string]any{"secretId": secretID, "disableRotation": disableRotation, "disableHeartbeat": disableHeartbeat}
	err := c.do(ctx, token, setAutomationMutation, vars, &out)
	return out.Secret, err
}
