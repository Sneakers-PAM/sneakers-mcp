// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package tools exposes the Sneakers MCP tool surface. Each tool is a thin
// mapping onto the gateway's machine GraphQL API, carrying the calling
// agent's own bearer token through unchanged. No authorization decisions are
// made here: the gateway resolves the token to a machine principal, and vault
// applies RACI and writes the audit trail.
package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// Input limits. They bound what one tool call can push through the bridge;
// the gateway and vault still apply their own validation.
const (
	maxIDLen         = 128
	maxNameLen       = 256
	maxQueryLen      = 256
	maxFieldKeyLen   = 128
	maxFieldValueLen = 16 << 10
	maxFields        = 32
)

const (
	toolFind     = "sneakers_find_secrets"
	toolGet      = "sneakers_get_secret"
	toolCreate   = "sneakers_create_secret"
	toolGenerate = "sneakers_generate_secret"
	toolMove     = "sneakers_move_secret"
	toolRetype   = "sneakers_change_secret_type"
	toolFolders  = "sneakers_list_folders"
	toolTypes    = "sneakers_list_secret_types"
	toolRedeem   = "sneakers_redeem_reveal"
)

// revealClientLabel names this bridge on the owner's approval page.
const revealClientLabel = "Sneakers MCP"

// errUnauthenticated is returned when a tool call arrives without a verified
// bearer. The HTTP auth middleware should make this unreachable; the check is
// a second, independent fail-closed gate so a wiring or transport change can
// never become an unauthenticated (or confused-deputy) call to the gateway.
var errUnauthenticated = errors.New("unauthenticated: this call carries no verified bearer token")

// errInvalidInput marks validation failures (for log classification only).
var errInvalidInput = errors.New("invalid input")

type toolset struct {
	gw  *gwclient.Client
	log zerolog.Logger

	checkPoll, checkWait time.Duration // zero: defaultCheckPoll / defaultCheckWait
}

// callerToken returns the verified caller's raw bearer token for this call.
// It requires both the TokenInfo the auth middleware attaches after
// verification and a well-formed Bearer header on the same request.
func callerToken(req *mcp.CallToolRequest) (token, subject string, err error) {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil || req.Extra.Header == nil {
		return "", "", errUnauthenticated
	}
	f := strings.Fields(req.Extra.Header.Get("Authorization"))
	if len(f) != 2 || !strings.EqualFold(f[0], "bearer") {
		return "", "", errUnauthenticated
	}
	return f[1], req.Extra.TokenInfo.UserID, nil
}

// run is the shared envelope for every tool: authenticate the call, validate
// input, invoke the gateway, classify and log the outcome. The log line
// carries the tool name, token subject and outcome only; never arguments,
// results, tokens or gateway error text.
func (t *toolset) run(req *mcp.CallToolRequest, tool string, validate func() error, call func(token string) error) error {
	start := time.Now()
	token, sub, err := callerToken(req)
	if err == nil {
		if verr := validate(); verr != nil {
			err = fmt.Errorf("%w: %v", errInvalidInput, verr)
		} else {
			err = toolError(call(token))
		}
	}
	t.log.Info().Str("tool", tool).Str("sub", sub).Str("outcome", outcome(err)).
		Dur("dur", time.Since(start)).Msg("mcp tool call")
	return err
}

func outcome(err error) string {
	var ge *gwclient.GraphQLError
	var se *gwclient.StatusError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, errUnauthenticated):
		return "unauthenticated"
	case errors.Is(err, errInvalidInput):
		return "invalid_input"
	case errors.As(err, &ge):
		return "gateway_denied_or_failed"
	case errors.As(err, &se):
		return fmt.Sprintf("gateway_http_%d", se.Code)
	default:
		return "error"
	}
}

// toolError turns a gateway failure into the tool-level error the model sees.
// GraphQL messages (RACI denial, not found) are relayed; transport details
// are not.
func toolError(err error) error {
	if err == nil {
		return nil
	}
	var ge *gwclient.GraphQLError
	var se *gwclient.StatusError
	switch {
	case errors.Is(err, gwclient.ErrNoToken):
		return errUnauthenticated
	case errors.Is(err, errInvalidInput):
		return err
	case errors.As(err, &ge):
		return fmt.Errorf("sneakers: %w", ge)
	case errors.As(err, &se) && (se.Code == 401 || se.Code == 403):
		return fmt.Errorf("the Sneakers gateway rejected the caller's credentials (%w)", se)
	case errors.As(err, &se):
		return fmt.Errorf("the Sneakers gateway failed (%w)", se)
	default:
		return errors.New("the Sneakers gateway could not be reached or returned an unusable response")
	}
}

// --- validation ---------------------------------------------------------

func checkLen(name, v string, limit int, required bool) error {
	if required && strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(v) > limit {
		return fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return nil
}

func checkAll(errs ...error) error { return errors.Join(errs...) }

func checkFields(fields []fieldIn) error {
	if len(fields) > maxFields {
		return fmt.Errorf("at most %d fields are allowed", maxFields)
	}
	seen := make(map[string]struct{}, len(fields))
	for i, f := range fields {
		if err := checkLen(fmt.Sprintf("fields[%d].key", i), f.Key, maxFieldKeyLen, true); err != nil {
			return err
		}
		// Never echo the value itself, only its position.
		if len(f.Value) > maxFieldValueLen {
			return fmt.Errorf("fields[%d].value exceeds %d bytes", i, maxFieldValueLen)
		}
		if _, dup := seen[f.Key]; dup {
			return fmt.Errorf("fields[%d].key %q is duplicated", i, f.Key)
		}
		seen[f.Key] = struct{}{}
	}
	return nil
}

// --- shared types -------------------------------------------------------

type secretSummary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FolderID string `json:"folderId"`
	TypeID   string `json:"typeId"`
	TargetID string `json:"targetId,omitempty"`

	RotationOptOut  bool `json:"rotationOptOut" jsonschema:"rotation is turned off for this secret"`
	HeartbeatOptOut bool `json:"heartbeatOptOut" jsonschema:"heartbeat checks are turned off for this secret"`
}

func summaryOf(s gwclient.SecretSummary) secretSummary {
	out := secretSummary{ID: s.ID, Name: s.Name, FolderID: s.FolderID, TypeID: s.TypeID,
		RotationOptOut: s.RotationOptOut, HeartbeatOptOut: s.HeartbeatOptOut}
	if s.TargetID != nil {
		out.TargetID = *s.TargetID
	}
	return out
}

type fieldIn struct {
	Key   string `json:"key" jsonschema:"field name, e.g. username"`
	Value string `json:"value" jsonschema:"field value"`
}

func fieldsOf(in []fieldIn) []gwclient.Field {
	out := make([]gwclient.Field, 0, len(in))
	for _, f := range in {
		out = append(out, gwclient.Field{Key: f.Key, Value: f.Value})
	}
	return out
}

// --- sneakers_find_secrets ----------------------------------------------

type findSecretsIn struct {
	Query    string `json:"query,omitempty" jsonschema:"case-insensitive substring match on the secret name"`
	FolderID string `json:"folderId,omitempty" jsonschema:"restrict to this folder id"`
	TypeID   string `json:"typeId,omitempty" jsonschema:"restrict to this secret type id"`
}
type findSecretsOut struct {
	Secrets []secretSummary `json:"secrets"`
}

func (t *toolset) findSecrets(ctx context.Context, req *mcp.CallToolRequest, in findSecretsIn) (*mcp.CallToolResult, findSecretsOut, error) {
	out := findSecretsOut{Secrets: []secretSummary{}}
	err := t.run(req, toolFind,
		func() error {
			return checkAll(checkLen("query", in.Query, maxQueryLen, false),
				checkLen("folderId", in.FolderID, maxIDLen, false),
				checkLen("typeId", in.TypeID, maxIDLen, false))
		},
		func(token string) error {
			found, err := t.gw.FindSecrets(ctx, token, in.Query, in.FolderID, in.TypeID)
			for _, s := range found {
				out.Secrets = append(out.Secrets, summaryOf(s))
			}
			return err
		})
	if err != nil {
		return nil, findSecretsOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_list_folders ----------------------------------------------

type listFoldersIn struct {
	Query    string `json:"query,omitempty" jsonschema:"case-insensitive substring match on the folder name"`
	ParentID string `json:"parentId,omitempty" jsonschema:"list only the direct children of this folder id"`
}
type folderOut struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ParentID  string `json:"parentId,omitempty"`
	Path      string `json:"path"`
	CanAuthor bool   `json:"canAuthor"`
}
type listFoldersOut struct {
	Folders []folderOut `json:"folders"`
}

func (t *toolset) listFolders(ctx context.Context, req *mcp.CallToolRequest, in listFoldersIn) (*mcp.CallToolResult, listFoldersOut, error) {
	out := listFoldersOut{Folders: []folderOut{}}
	err := t.run(req, toolFolders,
		func() error {
			return checkAll(checkLen("query", in.Query, maxQueryLen, false), checkLen("parentId", in.ParentID, maxIDLen, false))
		},
		func(token string) error {
			found, err := t.gw.ListFolders(ctx, token, in.Query, in.ParentID)
			for _, f := range found {
				out.Folders = append(out.Folders, folderOutOf(f))
			}
			return err
		})
	if err != nil {
		return nil, listFoldersOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_list_secret_types -----------------------------------------

type listSecretTypesIn struct{}
type typeFieldOut struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Required bool   `json:"required"`

	Sensitive bool `json:"sensitive" jsonschema:"holds a secret value; set it with sneakers-put, never through a tool call"`
}
type secretTypeOut struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Fields []typeFieldOut `json:"fields"`
}
type listSecretTypesOut struct {
	Types []secretTypeOut `json:"types"`
}

func (t *toolset) listSecretTypes(ctx context.Context, req *mcp.CallToolRequest, _ listSecretTypesIn) (*mcp.CallToolResult, listSecretTypesOut, error) {
	out := listSecretTypesOut{Types: []secretTypeOut{}}
	err := t.run(req, toolTypes,
		func() error { return nil },
		func(token string) error {
			types, err := t.gw.ListSecretTypes(ctx, token)
			for _, ty := range types {
				to := secretTypeOut{ID: ty.ID, Name: ty.Name, Fields: make([]typeFieldOut, 0, len(ty.Fields))}
				for _, f := range ty.Fields {
					to.Fields = append(to.Fields, typeFieldOut{Key: f.Key, Label: f.Label, Kind: f.Kind, Required: f.Required, Sensitive: f.Sensitive})
				}
				out.Types = append(out.Types, to)
			}
			return err
		})
	if err != nil {
		return nil, listSecretTypesOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_get_secret ------------------------------------------------

type getSecretIn struct {
	ID       string `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	FieldKey string `json:"fieldKey" jsonschema:"which field to read, e.g. password, notes or url"`
}
type getSecretOut struct {
	Value            string `json:"value"`
	ApprovalRequired bool   `json:"approvalRequired,omitempty"`
	ApprovalURL      string `json:"approvalUrl,omitempty"`
	UseID            string `json:"useId,omitempty"`
	ExpiresAtUnix    int64  `json:"expiresAtUnix,omitempty"`
	Message          string `json:"message,omitempty"`
}

func (t *toolset) getSecret(ctx context.Context, req *mcp.CallToolRequest, in getSecretIn) (*mcp.CallToolResult, getSecretOut, error) {
	var out getSecretOut
	err := t.run(req, toolGet,
		func() error {
			return checkAll(checkLen("id", in.ID, maxIDLen, true), checkLen("fieldKey", in.FieldKey, maxFieldKeyLen, true))
		},
		func(token string) error {
			v, err := t.gw.RevealField(ctx, token, in.ID, in.FieldKey)
			if !needsApproval(err) {
				out.Value = v
				return err
			}
			use, err := t.gw.PrepareReveal(ctx, token, in.ID, in.FieldKey, revealClientLabel)
			if err != nil {
				return err
			}
			if use.State == "APPROVED" {
				out.Value, _, err = t.gw.RedeemSecretUse(ctx, token, use.ID)
				return err
			}
			out = getSecretOut{
				ApprovalRequired: true, ApprovalURL: use.ApprovalURL, UseID: use.ID, ExpiresAtUnix: use.ExpiresAtUnix,
				Message: "The owner must approve this reveal. " + openApprovalNow(use.ApprovalURL),
			}
			return nil
		})
	if err != nil {
		return nil, getSecretOut{}, err
	}
	return nil, out, nil
}

// openApprovalNow asks the agent to open the page on the user's machine: this
// server runs in a cluster and can't, and a link left in a transcript tends to
// expire unseen.
func openApprovalNow(url string) string {
	return "Open approvalUrl in the user's browser now (" + url + ") with this environment's browser opener " +
		"($BROWSER, xdg-open or open), so the owner sees it before it expires. After they approve it with their " +
		"second factor, call " + toolRedeem + " again with useId within 60 seconds."
}

// needsApproval reports vault's refusal of a direct token reveal of a secret
// whose owner approves each one.
func needsApproval(err error) bool {
	var ge *gwclient.GraphQLError
	return errors.As(err, &ge) && strings.Contains(ge.Error(), "approval_required")
}

// --- sneakers_redeem_reveal ---------------------------------------------

type redeemRevealIn struct {
	UseID string `json:"useId" jsonschema:"the useId sneakers_get_secret returned with approvalRequired"`
}
type redeemRevealOut struct {
	Value       string `json:"value,omitempty"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalURL string `json:"approvalUrl,omitempty"`
	Message     string `json:"message,omitempty"`
}

func (t *toolset) redeemReveal(ctx context.Context, req *mcp.CallToolRequest, in redeemRevealIn) (*mcp.CallToolResult, redeemRevealOut, error) {
	var out redeemRevealOut
	err := t.run(req, toolRedeem,
		func() error { return checkLen("useId", in.UseID, maxIDLen, true) },
		func(token string) error {
			use, err := t.gw.SecretUse(ctx, token, in.UseID)
			if err != nil {
				return err
			}
			switch use.State {
			case "PENDING":
				out = redeemRevealOut{Pending: true, ApprovalURL: use.ApprovalURL,
					Message: "The owner hasn't approved this reveal yet. " + openApprovalNow(use.ApprovalURL)}
				return nil
			case "APPROVED":
				out.Value, _, err = t.gw.RedeemSecretUse(ctx, token, use.ID)
				return err
			default:
				return &gwclient.GraphQLError{Messages: []string{"this reveal is " + strings.ToLower(use.State) + "; ask for it again with " + toolGet}}
			}
		})
	if err != nil {
		return nil, redeemRevealOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_create_secret ---------------------------------------------

type createSecretIn struct {
	FolderID string    `json:"folderId" jsonschema:"destination folder id"`
	TypeID   string    `json:"typeId" jsonschema:"secret type id"`
	Name     string    `json:"name" jsonschema:"name for the new secret"`
	Fields   []fieldIn `json:"fields" jsonschema:"field values to store"`
	TargetID string    `json:"targetId,omitempty" jsonschema:"optional target id to associate"`

	DisableRotation  bool `json:"disableRotation,omitempty" jsonschema:"create the secret with rotation turned off; use it for credentials that must never rotate"`
	DisableHeartbeat bool `json:"disableHeartbeat,omitempty" jsonschema:"create the secret with heartbeat checks turned off"`
}
type createSecretOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) createSecret(ctx context.Context, req *mcp.CallToolRequest, in createSecretIn) (*mcp.CallToolResult, createSecretOut, error) {
	var out createSecretOut
	err := t.run(req, toolCreate,
		func() error {
			return checkAll(checkLen("folderId", in.FolderID, maxIDLen, true),
				checkLen("typeId", in.TypeID, maxIDLen, true),
				checkLen("name", in.Name, maxNameLen, true),
				checkLen("targetId", in.TargetID, maxIDLen, false),
				checkFields(in.Fields))
		},
		func(token string) error {
			s, err := t.gw.CreateSecret(ctx, token, in.FolderID, in.TypeID, in.Name, fieldsOf(in.Fields), in.TargetID,
				gwclient.Automation{DisableRotation: in.DisableRotation, DisableHeartbeat: in.DisableHeartbeat})
			if err == nil {
				out.Secret = summaryOf(*s)
			}
			return err
		})
	if err != nil {
		return nil, createSecretOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_generate_secret -------------------------------------------

type generateSecretIn struct {
	FolderID    string    `json:"folderId" jsonschema:"destination folder id"`
	TypeID      string    `json:"typeId" jsonschema:"secret type id; must declare a password field"`
	Name        string    `json:"name" jsonschema:"name for the new secret"`
	Fields      []fieldIn `json:"fields,omitempty" jsonschema:"non-generated fields such as username"`
	PolicyID    string    `json:"policyId,omitempty" jsonschema:"optional password policy id"`
	TargetID    string    `json:"targetId,omitempty" jsonschema:"optional target id to associate"`
	ReturnValue bool      `json:"returnValue,omitempty" jsonschema:"return the generated value; omit to store it without disclosing it"`

	DisableRotation  bool `json:"disableRotation,omitempty" jsonschema:"create the secret with rotation turned off; use it for credentials that must never rotate"`
	DisableHeartbeat bool `json:"disableHeartbeat,omitempty" jsonschema:"create the secret with heartbeat checks turned off"`
}
type generateSecretOut struct {
	Secret         secretSummary `json:"secret"`
	GeneratedValue string        `json:"generatedValue,omitempty"`
}

func (t *toolset) generateSecret(ctx context.Context, req *mcp.CallToolRequest, in generateSecretIn) (*mcp.CallToolResult, generateSecretOut, error) {
	var out generateSecretOut
	err := t.run(req, toolGenerate,
		func() error {
			return checkAll(checkLen("folderId", in.FolderID, maxIDLen, true),
				checkLen("typeId", in.TypeID, maxIDLen, true),
				checkLen("name", in.Name, maxNameLen, true),
				checkLen("policyId", in.PolicyID, maxIDLen, false),
				checkLen("targetId", in.TargetID, maxIDLen, false),
				checkFields(in.Fields))
		},
		func(token string) error {
			s, val, err := t.gw.GenerateSecret(ctx, token, in.FolderID, in.TypeID, in.Name, fieldsOf(in.Fields), in.PolicyID, in.TargetID, in.ReturnValue,
				gwclient.Automation{DisableRotation: in.DisableRotation, DisableHeartbeat: in.DisableHeartbeat})
			if err == nil {
				out = generateSecretOut{Secret: summaryOf(*s), GeneratedValue: val}
			}
			return err
		})
	if err != nil {
		return nil, generateSecretOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_move_secret -----------------------------------------------

type moveSecretIn struct {
	ID           string `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	DestFolderID string `json:"destFolderId" jsonschema:"folder id to move the secret into"`
}
type moveSecretOut struct {
	Secret secretSummary `json:"secret"`
}

func (t *toolset) moveSecret(ctx context.Context, req *mcp.CallToolRequest, in moveSecretIn) (*mcp.CallToolResult, moveSecretOut, error) {
	var out moveSecretOut
	err := t.run(req, toolMove,
		func() error {
			return checkAll(checkLen("id", in.ID, maxIDLen, true), checkLen("destFolderId", in.DestFolderID, maxIDLen, true))
		},
		func(token string) error {
			s, err := t.gw.MoveSecret(ctx, token, in.ID, in.DestFolderID)
			if err == nil {
				out.Secret = summaryOf(*s)
			}
			return err
		})
	if err != nil {
		return nil, moveSecretOut{}, err
	}
	return nil, out, nil
}

// --- sneakers_change_secret_type ----------------------------------------

type mappingIn struct {
	From string `json:"from" jsonschema:"existing field key, e.g. password"`
	To   string `json:"to" jsonschema:"field key of the new type that receives the value, e.g. note"`
}

type changeSecretTypeIn struct {
	ID           string      `json:"id" jsonschema:"secret id, as returned by sneakers_find_secrets"`
	NewTypeID    string      `json:"newTypeId" jsonschema:"secret type id to convert to"`
	FieldMapping []mappingIn `json:"fieldMapping,omitempty" jsonschema:"renames for fields whose key differs in the new type; unlisted fields keep their key"`
	Fields       []fieldIn   `json:"fields,omitempty" jsonschema:"values for new-type fields the existing values do not fill (e.g. a newly required field); cannot overwrite a carried-over value"`
}
type changeSecretTypeOut struct {
	Secret           secretSummary `json:"secret"`
	FieldKeys        []string      `json:"fieldKeys"`
	MovedToNotesKeys []string      `json:"movedToNotesKeys" jsonschema:"old field keys whose values had no field in the new type and were appended to its notes field (keys only)"`
	Automation       retypeAutoOut `json:"automation"`
}

type retypeAutoOut struct {
	Rotation  string `json:"rotation" jsonschema:"NONE (type never rotates), OFF (opted out) or ON"`
	Heartbeat string `json:"heartbeat" jsonschema:"NONE (type has none), OFF (opted out), NO_TARGET or ON"`
	Target    string `json:"target" jsonschema:"ATTACHED, NONE (type takes a target, the secret has none) or NOT_SUPPORTED (type takes no target; any target was detached)"`
	Note      string `json:"note" jsonschema:"what the change did to rotation, heartbeat and the target, and what to do next"`
}

// retypeNote spells out a type change's automation result for the agent.
func retypeNote(a gwclient.TypeChangeAutomation) string {
	var parts []string
	switch a.Rotation {
	case "OFF":
		parts = append(parts, "Rotation is off. Turn it on with "+toolSetAutomation+" (disableRotation: false) once the account is ready to rotate.")
	case "ON":
		parts = append(parts, "Rotation is on.")
	}
	switch a.Heartbeat {
	case "ON":
		parts = append(parts, "Heartbeat checks run against the target (the target needs a connection).")
	case "OFF":
		parts = append(parts, "Heartbeat checks are off.")
	case "NO_TARGET":
		parts = append(parts, "No heartbeat runs until a target is attached with sneakers_set_secret_target.")
	}
	if a.Rotation == "NONE" && a.Heartbeat == "NONE" {
		parts = append(parts, "The new type has no rotation or heartbeat.")
	}
	switch a.Target {
	case "ATTACHED":
		parts = append(parts, "The target was kept.")
	case "NOT_SUPPORTED":
		parts = append(parts, "The new type takes no target, so any target was detached.")
	}
	return strings.Join(parts, " ")
}

func checkMappings(m []mappingIn) error {
	if len(m) > maxFields {
		return fmt.Errorf("at most %d fieldMapping entries are allowed", maxFields)
	}
	seen := make(map[string]struct{}, len(m))
	for i, e := range m {
		if err := checkAll(checkLen(fmt.Sprintf("fieldMapping[%d].from", i), e.From, maxFieldKeyLen, true),
			checkLen(fmt.Sprintf("fieldMapping[%d].to", i), e.To, maxFieldKeyLen, true)); err != nil {
			return err
		}
		if _, dup := seen[e.From]; dup {
			return fmt.Errorf("fieldMapping[%d].from %q is duplicated", i, e.From)
		}
		seen[e.From] = struct{}{}
	}
	return nil
}

func (t *toolset) changeSecretType(ctx context.Context, req *mcp.CallToolRequest, in changeSecretTypeIn) (*mcp.CallToolResult, changeSecretTypeOut, error) {
	var out changeSecretTypeOut
	err := t.run(req, toolRetype,
		func() error {
			return checkAll(checkLen("id", in.ID, maxIDLen, true),
				checkLen("newTypeId", in.NewTypeID, maxIDLen, true),
				checkMappings(in.FieldMapping),
				checkFields(in.Fields))
		},
		func(token string) error {
			mapping := make([]gwclient.Mapping, 0, len(in.FieldMapping))
			for _, m := range in.FieldMapping {
				mapping = append(mapping, gwclient.Mapping{From: m.From, To: m.To})
			}
			res, err := t.gw.ChangeSecretType(ctx, token, in.ID, in.NewTypeID, mapping, fieldsOf(in.Fields))
			if err == nil {
				a := res.Automation
				out = changeSecretTypeOut{Secret: summaryOf(*res.Secret), FieldKeys: res.FieldKeys, MovedToNotesKeys: res.MovedToNotesKeys, Automation: retypeAutoOut{
					Rotation: a.Rotation, Heartbeat: a.Heartbeat, Target: a.Target, Note: retypeNote(a),
				}}
			}
			return err
		})
	if err != nil {
		return nil, changeSecretTypeOut{}, err
	}
	return nil, out, nil
}

// --- registration -------------------------------------------------------

func ptr[T any](v T) *T { return &v }

// Register adds every Sneakers tool to s. log receives one line per tool
// call (tool, subject, outcome); never arguments or results.
func Register(s *mcp.Server, gw *gwclient.Client, log zerolog.Logger) {
	t := &toolset{gw: gw, log: log}
	registerTargetTools(s, t)
	registerCheckTool(s, t)
	registerOrganizeTools(s, t)
	registerAutomationTool(s, t)
	registerUpdateTool(s, t)

	mcp.AddTool(s, &mcp.Tool{
		Name:        toolFind,
		Description: "Discover secrets the calling agent is permitted to read. Returns metadata only, never field values.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.findSecrets)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolFolders,
		Description: "List the folders the calling agent may read, with each folder's id, path and whether the " +
			"agent may create secrets there (canAuthor). Use it to find the folderId for sneakers_create_secret.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.listFolders)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolTypes,
		Description: "List the secret types, with each type's id and field keys (kind, required, sensitive). Use it to pick " +
			"the typeId and field keys for sneakers_create_secret. Fields a type doesn't declare are still stored " +
			"but may not show in the UI.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.listSecretTypes)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolGet,
		Description: "Read one field of one secret. Non-sensitive fields (notes, URL, endpoint, description) come " +
			"back directly and are audited as a read. A sensitive field (password, key, token) is a reveal, audited as " +
			"one. Both are audited as the token's user, or the service account, and fail if the caller lacks read " +
			"access. Some secrets need the owner's approval in the browser for each reveal of a sensitive field: then " +
			"no value comes back, only approvalRequired, an approvalUrl and a useId. Then open approvalUrl in the " +
			"user's browser straight away with the environment's browser opener, and after the owner approves, call " +
			toolRedeem + " with the useId.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, t.getSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolRedeem,
		Description: "Collect a reveal the owner has approved, using the useId from sneakers_get_secret. Returns " +
			"pending (with the approvalUrl) until they approve: if it wasn't opened yet, open approvalUrl in the user's " +
			"browser with the environment's browser opener, then call again after they approve. The value is released " +
			"once, within 60 seconds of approval.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, t.redeemReveal)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolCreate,
		Description: "Store a new secret with caller-supplied field values. Requires author access to the folder. " +
			"Every value passed here is written into this session's transcript. When a value already exists on disk " +
			"(a key file, a password file, another tool's output), or would otherwise pass through the transcript, " +
			"do not call this tool: have the user run the local sneakers-put command " +
			"(sneakers-put -folder <id> -type <id> -name <name> -field password=@file), which reads the value itself " +
			"and prints only the id and name. " + neverRotateHint,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.createSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolGenerate,
		Description: "Generate a policy-compliant password and store it as a new secret. Set returnValue only if the caller " +
			"genuinely needs the plaintext back: a returned value is written into this session's transcript. To store a " +
			"value that already exists on disk, use the local sneakers-put command instead of passing it here. " + neverRotateHint,
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.generateSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolMove,
		Description: "Move one secret to a different folder. WARNING: this changes who can access the secret, " +
			"because access follows the folder. People and agents with rights only on the old folder lose access, " +
			"and those with rights on the new folder gain it. Requires author access on BOTH the current and the " +
			"destination folder. Moving into a personal folder is refused. The secret keeps its id, values and " +
			"history. Audited against the agent's service account.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, t.moveSecret)

	mcp.AddTool(s, &mcp.Tool{
		Name: toolRetype,
		Description: "Change the type of one secret, re-keying its stored values into the new type's fields. " +
			"WARNING: this restructures the secret, so anything that reads its fields by key will see the new keys. " +
			"It never silently discards a value. Every non-empty field carries over under the same key or through " +
			"fieldMapping. A value with no field in the new type is appended to the new type's notes field as a " +
			"line \"[moved from <key>]: <value as a JSON string>\"; the result's movedToNotesKeys lists those keys. " +
			"The call fails, naming the fields, if the new type " +
			"has no notes field, if the notes would exceed their max length, or if the value is sensitive and the " +
			"notes field is not at least as protected (most notes fields are not sensitive, so map sensitive fields " +
			"explicitly). Sensitive values can only move into sensitive fields. Use fields only to fill new " +
			"fields the new type requires. Any type can be converted into or out of any other, including types with " +
			"rotation or heartbeat (e.g. AD/Windows/database accounts) and the certificate type. After a change into a " +
			"rotation type, rotation stays off until you turn it on with " + toolSetAutomation + "; heartbeat runs only " +
			"once the secret has a target; a type that takes no target detaches it. Into the certificate type, the " +
			"certificate and key fields must hold valid PEM. The result's automation says what happened. Removing " +
			"checkout from a plain checkout type is refused. The previous values stay in version history. Requires " +
			"author access. Audited against the agent's service account.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, t.changeSecretType)
}
