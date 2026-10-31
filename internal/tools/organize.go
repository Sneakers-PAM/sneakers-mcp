// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const (
	toolRenameSecret = "sneakers_rename_secret"
	toolCreateFolder = "sneakers_create_folder"
	toolRenameFolder = "sneakers_rename_folder"
)

// checkName validates a secret or folder name. Folder paths are joined with
// '/', so a name containing one would read as a different path.
func checkName(v string) error {
	if err := checkLen("name", v, maxNameLen, true); err != nil {
		return err
	}
	if strings.Contains(v, "/") {
		return errors.New("name must not contain '/'")
	}
	return nil
}

func folderOutOf(f gwclient.Folder) folderOut {
	fo := folderOut{ID: f.ID, Name: f.Name, Path: f.Path, CanAuthor: f.CanAuthor}
	if f.ParentID != nil {
		fo.ParentID = *f.ParentID
	}
	return fo
}

// --- sneakers_rename_secret -----------------------------------------------

type renameSecretIn struct {
	ID   string `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	Name string `json:"name" jsonschema:"the new name; no '/'"`
}
type renameSecretOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) renameSecret(ctx context.Context, req *mcp.CallToolRequest, in renameSecretIn) (*mcp.CallToolResult, renameSecretOut, error) {
	var out renameSecretOut
	err := t.run(req, toolRenameSecret,
		func() error { return checkAll(checkLen("id", in.ID, maxIDLen, true), checkName(in.Name)) },
		func(token string) error {
			s, err := t.gw.RenameSecret(ctx, token, in.ID, in.Name)
			if err == nil {
				out.Secret = summaryOf(*s)
			}
			return err
		})
	if err != nil {
		return nil, renameSecretOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_create_folder -----------------------------------------------

type createFolderIn struct {
	ParentID string `json:"parentId,omitempty" jsonschema:"folder id to create the new folder in, from sneakers_list_folders; leave it out for a top-level folder"`
	Name     string `json:"name" jsonschema:"name of the new folder; no '/'"`
}
type folderResultOut struct {
	Folder folderOut `json:"folder"`
}

func (t *toolset) createFolder(ctx context.Context, req *mcp.CallToolRequest, in createFolderIn) (*mcp.CallToolResult, folderResultOut, error) {
	var out folderResultOut
	err := t.run(req, toolCreateFolder,
		func() error { return checkAll(checkLen("parentId", in.ParentID, maxIDLen, false), checkName(in.Name)) },
		func(token string) error {
			f, err := t.gw.CreateFolder(ctx, token, in.ParentID, in.Name)
			if err != nil {
				if in.ParentID == "" {
					return explainTopLevelRefusal(err)
				}
				return err
			}
			out.Folder = folderOutOf(*f)
			return nil
		})
	if err != nil {
		return nil, folderResultOut{}, err
	}
	return nil, out, nil
}

// explainTopLevelRefusal rewords the vault's two refusals of a top-level
// create so the agent knows what stops it and what to do instead. Anything else
// keeps the vault's own words. The service-account refusal carries no reason,
// so it's matched on its text; if that text changes the vault's message is
// relayed as it stands, which is still accurate.
func explainTopLevelRefusal(err error) error {
	var ge *gwclient.GraphQLError
	if !errors.As(err, &ge) {
		return err
	}
	for _, d := range ge.Details {
		switch {
		case d.Reason == "TOP_LEVEL_FOLDERS_RESTRICTED":
			return &gwclient.GraphQLError{Messages: []string{"PERMISSION_DENIED (TOP_LEVEL_FOLDERS_RESTRICTED): an admin turned on the security " +
				"setting \"Restrict top-level folders to admins\", so only an admin can create a top-level folder. Ask an admin, or " +
				"pass parentId to create it under a folder you can author."}}
		case d.Code == "INVALID_ARGUMENT" && strings.Contains(d.Message, "parent_id is required"):
			return &gwclient.GraphQLError{Messages: []string{"INVALID_ARGUMENT: a service account can't create a top-level folder, " +
				"because nothing would own it. Pass parentId to create it under a folder you can author."}}
		}
	}
	return err
}

// --- sneakers_rename_folder -----------------------------------------------

type renameFolderIn struct {
	ID   string `json:"id" jsonschema:"folder id, from sneakers_list_folders"`
	Name string `json:"name" jsonschema:"the new name; no '/'"`
}

func (t *toolset) renameFolder(ctx context.Context, req *mcp.CallToolRequest, in renameFolderIn) (*mcp.CallToolResult, folderResultOut, error) {
	var out folderResultOut
	err := t.run(req, toolRenameFolder,
		func() error { return checkAll(checkLen("id", in.ID, maxIDLen, true), checkName(in.Name)) },
		func(token string) error {
			f, err := t.gw.RenameFolder(ctx, token, in.ID, in.Name)
			if err == nil {
				out.Folder = folderOutOf(*f)
			}
			return err
		})
	if err != nil {
		return nil, folderResultOut{}, err
	}
	return nil, out, nil
}

func registerOrganizeTools(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolRenameSecret,
		Description: "Rename one secret. Only the name changes: field values are never read, changed or returned, and " +
			"the id, folder and history stay the same. Requires author access to the secret's folder. Names may not " +
			"contain '/'. Audited with the old and new names.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.renameSecret)
	mcp.AddTool(s, &mcp.Tool{
		Name: toolCreateFolder,
		Description: "Create a folder. With parentId, the token can create it only under a parent it can author (canAuthor " +
			"in sneakers_list_folders). Leave parentId out for a top-level folder, owned by the token's user: any personal " +
			"token may, unless an admin turned on the security setting \"Restrict top-level folders to admins\", which limits " +
			"it to admins and refuses anyone else with PERMISSION_DENIED (TOP_LEVEL_FOLDERS_RESTRICTED). A service account " +
			"always needs parentId and is refused with INVALID_ARGUMENT without it. Never inside another user's Personal " +
			"tree, and never directly under the personal folders root; a personal token may create inside its own user's " +
			"Personal tree. A sibling folder with the same name (case-insensitive) is refused. Names may not contain '/'. " +
			"The returned path is the folder's own name; use sneakers_list_folders for the full path. Audited.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.createFolder)
	mcp.AddTool(s, &mcp.Tool{
		Name: toolRenameFolder,
		Description: "Rename one folder. The token can rename only folders it can author, which includes folders in " +
			"its own Personal tree but never another user's. Access, contents and secret values are unchanged. A sibling " +
			"folder with the same name is refused. Names may not contain '/'. The returned path is the folder's own " +
			"name; use sneakers_list_folders for the full path. Audited with the old and new names.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.renameFolder)
}
