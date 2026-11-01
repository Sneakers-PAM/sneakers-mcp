// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
)

const secretTypeFields = `id name fields{key label kind required sensitive}`

const extensionPacksQuery = `query ExtensionPacks{ availableExtensions{` + secretTypeFields + `} }`

// ListExtensionPacks lists the catalogued packs that aren't installed yet.
func (c *Client) ListExtensionPacks(ctx context.Context, token string) ([]SecretType, error) {
	var out struct {
		Packs []SecretType `json:"availableExtensions"`
	}
	if err := c.do(ctx, token, extensionPacksQuery, map[string]any{}, &out); err != nil {
		return nil, err
	}
	if out.Packs == nil {
		out.Packs = []SecretType{}
	}
	return out.Packs, nil
}

const importExtensionMutation = `mutation ImportExtension($id:ID!){ importExtension(id:$id){` + secretTypeFields + `} }`

// ImportExtensionPack activates a catalogued pack by id.
func (c *Client) ImportExtensionPack(ctx context.Context, token, id string) (*SecretType, error) {
	var out struct {
		Type *SecretType `json:"importExtension"`
	}
	if err := c.do(ctx, token, importExtensionMutation, map[string]any{"id": id}, &out); err != nil {
		return nil, err
	}
	if out.Type == nil {
		return nil, errors.New("gateway returned no secret type")
	}
	return out.Type, nil
}
