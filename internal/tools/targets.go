// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const (
	toolConnections = "sneakers_list_connections"
	toolTargets     = "sneakers_list_targets"
	toolSaveTarget  = "sneakers_save_target"
	toolSetTarget   = "sneakers_set_secret_target"

	maxHostnameLen = 253
	maxDescLen     = 1024
)

// validHostname accepts an IP address or an RFC 1123 host name; anything else
// (a URL, a space, an empty label) is refused before it reaches the vault.
func validHostname(h string) error {
	if net.ParseIP(h) != nil {
		return nil
	}
	if h == "" || len(h) > maxHostnameLen {
		return errors.New("hostname must be 1-253 characters")
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !validLabel(label) {
			return errors.New("hostname labels are 1-63 letters, digits or '-', not starting or ending with '-'")
		}
	}
	return nil
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	return strings.IndexFunc(l, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-'
	}) < 0
}

// --- sneakers_list_connections --------------------------------------------

type listConnectionsIn struct{}
type connectionOut struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	UseTLS      bool   `json:"useTls"`
	TargetCount int    `json:"targetCount"`
}
type listConnectionsOut struct {
	Connections []connectionOut `json:"connections"`
}

func (t *toolset) listConnections(ctx context.Context, req *mcp.CallToolRequest, _ listConnectionsIn) (*mcp.CallToolResult, listConnectionsOut, error) {
	out := listConnectionsOut{Connections: []connectionOut{}}
	err := t.run(req, toolConnections, func() error { return nil }, func(token string) error {
		cs, err := t.gw.ListConnections(ctx, token)
		for _, c := range cs {
			out.Connections = append(out.Connections, connectionOut(c))
		}
		return err
	})
	if err != nil {
		return nil, listConnectionsOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_list_targets ------------------------------------------------

type listTargetsIn struct {
	Query        string `json:"query,omitempty" jsonschema:"case-insensitive match on the target's name, hostname or domain"`
	ConnectionID string `json:"connectionId,omitempty" jsonschema:"only targets bound to this connection"`
}
type targetOut struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Kind         string `json:"kind,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Realm        string `json:"realm,omitempty"`
	ConnectionID string `json:"connectionId"`
	Description  string `json:"description,omitempty"`
	Shared       bool   `json:"shared" jsonschema:"published by an admin; only an admin can edit it"`
	SecretCount  int    `json:"secretCount"`
}
type listTargetsOut struct {
	Targets []targetOut `json:"targets"`
}

func targetOutOf(t gwclient.Target) targetOut {
	return targetOut{
		ID: t.ID, Name: t.Name, Hostname: t.Hostname, Kind: t.Kind, Domain: t.Domain, Realm: t.Realm,
		ConnectionID: t.ConnectionID, Description: t.Description, Shared: t.OwnerUserID == "", SecretCount: t.SecretCount,
	}
}

func (t *toolset) listTargets(ctx context.Context, req *mcp.CallToolRequest, in listTargetsIn) (*mcp.CallToolResult, listTargetsOut, error) {
	out := listTargetsOut{Targets: []targetOut{}}
	err := t.run(req, toolTargets,
		func() error {
			return checkAll(checkLen("query", in.Query, maxQueryLen, false), checkLen("connectionId", in.ConnectionID, maxIDLen, false))
		},
		func(token string) error {
			ts, err := t.gw.ListTargets(ctx, token, in.Query, in.ConnectionID)
			for _, tg := range ts {
				out.Targets = append(out.Targets, targetOutOf(tg))
			}
			return err
		})
	if err != nil {
		return nil, listTargetsOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_save_target -------------------------------------------------

type saveTargetIn struct {
	ID           string `json:"id,omitempty" jsonschema:"omit to create; set to update one of your own targets"`
	Name         string `json:"name" jsonschema:"display name, e.g. ad.example.org domain controllers"`
	Hostname     string `json:"hostname" jsonschema:"host name or IP the connector reaches, e.g. dc1.ad.example.org"`
	Kind         string `json:"kind,omitempty" jsonschema:"e.g. windows, unix, directory"`
	Domain       string `json:"domain,omitempty" jsonschema:"AD/DNS domain, for Windows targets"`
	Realm        string `json:"realm,omitempty" jsonschema:"Kerberos realm, usually the domain upper-cased"`
	ConnectionID string `json:"connectionId" jsonschema:"from sneakers_list_connections"`
	Description  string `json:"description,omitempty"`
}
type saveTargetOut struct {
	Target targetOut `json:"target"`
}

func (t *toolset) saveTarget(ctx context.Context, req *mcp.CallToolRequest, in saveTargetIn) (*mcp.CallToolResult, saveTargetOut, error) {
	var out saveTargetOut
	err := t.run(req, toolSaveTarget,
		func() error {
			return checkAll(checkLen("id", in.ID, maxIDLen, false), checkLen("name", in.Name, maxNameLen, true),
				validHostname(in.Hostname), checkLen("kind", in.Kind, maxNameLen, false), checkLen("domain", in.Domain, maxHostnameLen, false),
				checkLen("realm", in.Realm, maxHostnameLen, false), checkLen("connectionId", in.ConnectionID, maxIDLen, true),
				checkLen("description", in.Description, maxDescLen, false))
		},
		func(token string) error {
			tg, err := t.gw.SaveTarget(ctx, token, gwclient.TargetInput(in))
			out.Target = targetOutOf(tg)
			return err
		})
	if err != nil {
		return nil, saveTargetOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_set_secret_target -------------------------------------------

type setSecretTargetIn struct {
	SecretID string `json:"secretId"`
	TargetID string `json:"targetId,omitempty" jsonschema:"omit to detach the secret's target"`
}
type setSecretTargetOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) setSecretTarget(ctx context.Context, req *mcp.CallToolRequest, in setSecretTargetIn) (*mcp.CallToolResult, setSecretTargetOut, error) {
	var out setSecretTargetOut
	err := t.run(req, toolSetTarget,
		func() error {
			return checkAll(checkLen("secretId", in.SecretID, maxIDLen, true), checkLen("targetId", in.TargetID, maxIDLen, false))
		},
		func(token string) error {
			s, err := t.gw.SetSecretTarget(ctx, token, in.SecretID, in.TargetID)
			out.Secret = summaryOf(s)
			return err
		})
	if err != nil {
		return nil, setSecretTargetOut{}, err
	}
	return nil, out, nil
}

func registerTargetTools(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        toolConnections,
		Description: "List the connection profiles (protocol, port, TLS) a target can bind to. Connections are managed by admins in the Sneakers admin app.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.listConnections)
	mcp.AddTool(s, &mcp.Tool{
		Name: toolTargets,
		Description: "List the targets (systems secrets are validated against or rotated on) you can see: shared ones " +
			"and your own. Check here before creating one, so a credential is attached to the existing target.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.listTargets)
	mcp.AddTool(s, &mcp.Tool{
		Name: toolSaveTarget,
		Description: "Create a target, or update one of your own. A new target is personal to you; shared targets are " +
			"published by admins. When you store an account that belongs to a system, create or find its target and " +
			"attach it with sneakers_set_secret_target instead of leaving the secret without one.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.saveTarget)
	mcp.AddTool(s, &mcp.Tool{
		Name:        toolSetTarget,
		Description: "Attach a target to a secret you can author, or detach it by omitting targetId. The target must be shared or your own.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.setSecretTarget)
}
