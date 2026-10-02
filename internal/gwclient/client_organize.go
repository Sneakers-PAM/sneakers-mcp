// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"errors"
)

const renameSecretMutation = `mutation RenameSecret($id:ID!,$name:String!){
  renameSecretForPrincipal(id:$id,name:$name){` + summaryFields + `}
}`

// RenameSecret changes a secret's name. Field values are neither read nor
// returned.
func (c *Client) RenameSecret(ctx context.Context, token, id, name string) (*SecretSummary, error) {
	var out struct {
		Secret *SecretSummary `json:"renameSecretForPrincipal"`
	}
	if err := c.do(ctx, token, renameSecretMutation, map[string]any{"id": id, "name": name}, &out); err != nil {
		return nil, err
	}
	if out.Secret == nil {
		return nil, errors.New("gateway returned no secret")
	}
	return out.Secret, nil
}

const folderFields = `id name parentId path canAuthor`

const createFolderMutation = `mutation CreateFolder($parentId:ID!,$name:String!){
  createFolderForPrincipal(parentId:$parentId,name:$name){` + folderFields + `}
}`

// CreateFolder creates a folder under parentID.
func (c *Client) CreateFolder(ctx context.Context, token, parentID, name string) (*Folder, error) {
	var out struct {
		Folder *Folder `json:"createFolderForPrincipal"`
	}
	if err := c.do(ctx, token, createFolderMutation, map[string]any{"parentId": parentID, "name": name}, &out); err != nil {
		return nil, err
	}
	if out.Folder == nil {
		return nil, errors.New("gateway returned no folder")
	}
	return out.Folder, nil
}

const renameFolderMutation = `mutation RenameFolder($id:ID!,$name:String!){
  renameFolderForPrincipal(id:$id,name:$name){` + folderFields + `}
}`

// RenameFolder changes a folder's name.
func (c *Client) RenameFolder(ctx context.Context, token, id, name string) (*Folder, error) {
	var out struct {
		Folder *Folder `json:"renameFolderForPrincipal"`
	}
	if err := c.do(ctx, token, renameFolderMutation, map[string]any{"id": id, "name": name}, &out); err != nil {
		return nil, err
	}
	if out.Folder == nil {
		return nil, errors.New("gateway returned no folder")
	}
	return out.Folder, nil
}
