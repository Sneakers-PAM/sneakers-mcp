// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolListExtensionPacks  = "sneakers_list_extension_packs"
	toolImportExtensionPack = "sneakers_import_extension_pack"
)

func secretTypeOutOf(ty gwclient.SecretType) secretTypeOut {
	out := secretTypeOut{ID: ty.ID, Name: ty.Name, Fields: make([]typeFieldOut, 0, len(ty.Fields))}
	for _, f := range ty.Fields {
		out.Fields = append(out.Fields, typeFieldOut{Key: f.Key, Label: f.Label, Kind: f.Kind, Required: f.Required, Sensitive: f.Sensitive})
	}
	return out
}

// --- sneakers_list_extension_packs --------------------------------------

type listExtensionPacksIn struct{}
type listExtensionPacksOut struct {
	Packs []secretTypeOut `json:"packs"`
}

func (t *toolset) listExtensionPacks(ctx context.Context, req *mcp.CallToolRequest, _ listExtensionPacksIn) (*mcp.CallToolResult, listExtensionPacksOut, error) {
	out := listExtensionPacksOut{Packs: []secretTypeOut{}}
	err := t.run(req, toolListExtensionPacks,
		func() error { return nil },
		func(token string) error {
			packs, err := t.gw.ListExtensionPacks(ctx, token)
			for _, p := range packs {
				out.Packs = append(out.Packs, secretTypeOutOf(p))
			}
			return err
		})
	if err != nil {
		return nil, listExtensionPacksOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_import_extension_pack -------------------------------------

type importExtensionPackIn struct {
	ID string `json:"id" jsonschema:"pack id, as returned by sneakers_list_extension_packs"`
}
type importExtensionPackOut struct {
	Type secretTypeOut `json:"type"`
}

func (t *toolset) importExtensionPack(ctx context.Context, req *mcp.CallToolRequest, in importExtensionPackIn) (*mcp.CallToolResult, importExtensionPackOut, error) {
	var out importExtensionPackOut
	err := t.run(req, toolImportExtensionPack,
		func() error { return checkLen("id", in.ID, maxIDLen, true) },
		func(token string) error {
			ty, err := t.gw.ImportExtensionPack(ctx, token, in.ID)
			if err != nil {
				return err
			}
			out.Type = secretTypeOutOf(*ty)
			return nil
		})
	if err != nil {
		return nil, importExtensionPackOut{}, err
	}
	return nil, out, nil
}

func registerExtensionTools(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolListExtensionPacks,
		Description: "List the extension packs that can be activated: catalogued secret types that aren't installed " +
			"yet, each with its id and field keys. Any caller may list them. Activate one with " +
			"sneakers_import_extension_pack.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.listExtensionPacks)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolImportExtensionPack,
		Description: "Activate a catalogued extension pack by id, adding its secret type for everyone. Only a personal " +
			"token whose user is a site admin or root may; anyone else is refused with PERMISSION_DENIED " +
			"(NOT_SITE_ADMIN), and the refusal is audited. A pack already installed is refused with ALREADY_EXISTS. " +
			"Every activation is in the audit log with the user, the pack and the MCP as its source. Only catalogued " +
			"packs: a pack can't be pasted in through this tool.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.importExtensionPack)
}
