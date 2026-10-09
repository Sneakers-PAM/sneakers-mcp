// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package gwclient calls the Sneakers gateway's machine GraphQL endpoint
// (/machine/graphql) on behalf of a verified agent, forwarding that agent's
// own bearer token. It performs no authorization of its own: the gateway
// resolves the token to a machine principal and vault applies RACI.
//
// It holds no credentials. Every call takes the caller's token as an
// argument; nothing is cached between calls.
package gwclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxResponseBytes caps what we read back from the gateway.
	maxResponseBytes = 4 << 20
	// maxErrorMessageLen caps a relayed GraphQL error message.
	maxErrorMessageLen = 512
	defaultTimeout     = 30 * time.Second
)

// ErrNoToken is returned, without any network call, when the caller's token
// is empty.
var ErrNoToken = errors.New("gwclient: no caller token")

// StatusError is a non-200 HTTP answer from the gateway. The response body is
// deliberately not retained.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("gateway returned HTTP %d", e.Code) }

// GraphQLError carries the gateway's errors[] messages (e.g. a RACI denial).
type GraphQLError struct{ Messages []string }

func (e *GraphQLError) Error() string { return strings.Join(e.Messages, "; ") }

// SecretSummary mirrors the gateway's metadata-only SecretSummary.
type SecretSummary struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	FolderID string  `json:"folderId"`
	TypeID   string  `json:"typeId"`
	TargetID *string `json:"targetId,omitempty"`

	RotationOptOut  bool `json:"rotationOptOut"`
	HeartbeatOptOut bool `json:"heartbeatOptOut"`

	// Placement is set on a create or generate only.
	Placement *Placement `json:"placement,omitempty"`
}

// Placement is where the gateway stored a new secret and why. A personal
// token's secret that names its owner goes to the owner's Personal folder
// unless KeepFolder is set. Rule is REQUESTED, PERSONAL_DEFAULT,
// KEPT_BY_CALLER, ALREADY_PERSONAL or NO_PERSONAL_FOLDER; Reason names the
// matching part, never a value.
type Placement struct {
	FolderID          string `json:"folderId"`
	RequestedFolderID string `json:"requestedFolderId"`
	Rule              string `json:"rule"`
	Reason            string `json:"reason"`
}

// placementFields is the placement selection for a create or generate.
const placementFields = ` placement{folderId requestedFolderId rule reason}`

// summaryFields is the selection every SecretSummary result uses, so no
// operation drops a field the others return.
const summaryFields = `id name folderId typeId targetId rotationOptOut heartbeatOptOut`

// Automation opts a new secret out of rotation and/or heartbeat, so a
// credential that must never rotate never gets a schedule. KeepFolder opts
// out of the gateway's Personal-folder default for a secret that names its
// caller.
type Automation struct {
	DisableRotation  bool
	DisableHeartbeat bool
	KeepFolder       bool
}

// automationVars adds the opt-outs to a create or generate call. An unset opt-out is
// sent as null so the gateway applies its default.
func automationVars(vars map[string]any, auto []Automation) {
	var a Automation
	if len(auto) > 0 {
		a = auto[0]
	}
	vars["disableRotation"], vars["disableHeartbeat"] = nilIfFalse(a.DisableRotation), nilIfFalse(a.DisableHeartbeat)
	vars["keepFolder"] = nilIfFalse(a.KeepFolder)
}

func nilIfFalse(b bool) any {
	if !b {
		return nil
	}
	return true
}

// Field is one SecretFieldInput.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Client is a stateless machine-GraphQL client.
type Client struct {
	endpoint string
	hc       *http.Client
}

// New returns a client for endpoint. When hc is nil a client with a 30s
// timeout is used. Redirects are never followed, whichever client is given,
// so the caller's bearer can never be replayed to another URL.
func New(endpoint string, hc *http.Client) *Client {
	var c http.Client
	if hc != nil {
		c = *hc
	} else {
		c.Timeout = defaultTimeout
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{endpoint: endpoint, hc: &c}
}

// do executes one GraphQL operation as the caller identified by token and
// decodes data into out.
func (c *Client) do(ctx context.Context, token, query string, vars map[string]any, out any) error {
	if strings.TrimSpace(token) == "" {
		return ErrNoToken
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token) // the agent's own token
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("gateway request failed: %w", scrubURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return &StatusError{Code: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("gateway response read failed: %w", err)
	}
	if len(body) > maxResponseBytes {
		return errors.New("gateway response exceeds size limit")
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return errors.New("gateway response is not valid GraphQL JSON")
	}
	if len(env.Errors) > 0 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			m := e.Message
			if len(m) > maxErrorMessageLen {
				m = m[:maxErrorMessageLen] + "..."
			}
			msgs = append(msgs, m)
		}
		return &GraphQLError{Messages: msgs}
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return errors.New("gateway response has no data")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errors.New("gateway response has an unexpected shape")
	}
	return nil
}

// scrubURLError drops the *url.Error wrapper's URL, keeping only the cause.
// The endpoint is not secret, but this keeps errors terse and stable.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

const findQuery = `query Find($query:String,$folderId:ID,$typeId:ID){
  findSecretsForPrincipal(query:$query,folderId:$folderId,typeId:$typeId){` + summaryFields + `}
}`

// FindSecrets lists metadata of secrets the caller may read.
func (c *Client) FindSecrets(ctx context.Context, token, query, folderID, typeID string) ([]SecretSummary, error) {
	var out struct {
		Find []SecretSummary `json:"findSecretsForPrincipal"`
	}
	vars := map[string]any{"query": nilIfEmpty(query), "folderId": nilIfEmpty(folderID), "typeId": nilIfEmpty(typeID)}
	if err := c.do(ctx, token, findQuery, vars, &out); err != nil {
		return nil, err
	}
	if out.Find == nil {
		out.Find = []SecretSummary{}
	}
	return out.Find, nil
}

const foldersQuery = `query Folders($query:String,$parentId:ID){
  foldersForPrincipal(query:$query,parentId:$parentId){id name parentId path canAuthor}
}`

// Folder is one folder the caller may read, from foldersForPrincipal.
type Folder struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	ParentID  *string `json:"parentId,omitempty"`
	Path      string  `json:"path"`
	CanAuthor bool    `json:"canAuthor"`
}

// ListFolders lists the folders the caller may read, optionally filtered by
// name substring and direct parent.
func (c *Client) ListFolders(ctx context.Context, token, query, parentID string) ([]Folder, error) {
	var out struct {
		Folders []Folder `json:"foldersForPrincipal"`
	}
	vars := map[string]any{"query": nilIfEmpty(query), "parentId": nilIfEmpty(parentID)}
	if err := c.do(ctx, token, foldersQuery, vars, &out); err != nil {
		return nil, err
	}
	if out.Folders == nil {
		out.Folders = []Folder{}
	}
	return out.Folders, nil
}

const typesQuery = `query Types{ secretTypes{id name fields{key label kind required sensitive}} }`

// TypeField is one field a secret type declares.
type TypeField struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Required bool   `json:"required"`

	Sensitive bool `json:"sensitive"`
}

// SecretType is one entry of the vault type catalog.
type SecretType struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Fields []TypeField `json:"fields"`
}

// ListSecretTypes lists the vault's secret type catalog.
func (c *Client) ListSecretTypes(ctx context.Context, token string) ([]SecretType, error) {
	var out struct {
		Types []SecretType `json:"secretTypes"`
	}
	if err := c.do(ctx, token, typesQuery, map[string]any{}, &out); err != nil {
		return nil, err
	}
	if out.Types == nil {
		out.Types = []SecretType{}
	}
	return out.Types, nil
}

const revealQuery = `mutation Reveal($id:ID!,$fieldKey:String!){ revealSecretFieldForPrincipal(id:$id,fieldKey:$fieldKey) }`

// RevealField returns one field of one secret. Vault audits a non-sensitive
// field as a read and a sensitive one as a reveal.
func (c *Client) RevealField(ctx context.Context, token, id, fieldKey string) (string, error) {
	var out struct {
		Value *string `json:"revealSecretFieldForPrincipal"`
	}
	if err := c.do(ctx, token, revealQuery, map[string]any{"id": id, "fieldKey": fieldKey}, &out); err != nil {
		return "", err
	}
	if out.Value == nil {
		return "", errors.New("gateway returned no value")
	}
	return *out.Value, nil
}

const createQuery = `mutation Create($folderId:ID!,$typeId:ID!,$name:String!,$fields:[SecretFieldInput!]!,$targetId:ID,$disableRotation:Boolean,$disableHeartbeat:Boolean,$keepFolder:Boolean){
  createSecretForPrincipal(folderId:$folderId,typeId:$typeId,name:$name,fields:$fields,targetId:$targetId,disableRotation:$disableRotation,disableHeartbeat:$disableHeartbeat,keepFolder:$keepFolder){` + summaryFields + placementFields + `}
}`

// CreateSecret stores a secret with caller-supplied fields. At most one
// Automation is used. The gateway may store it in the caller's Personal
// folder instead of folderID; the summary's Placement says where and why.
func (c *Client) CreateSecret(ctx context.Context, token, folderID, typeID, name string, fields []Field, targetID string, auto ...Automation) (*SecretSummary, error) {
	var out struct {
		Secret *SecretSummary `json:"createSecretForPrincipal"`
	}
	vars := map[string]any{"folderId": folderID, "typeId": typeID, "name": name, "fields": fieldsOrEmpty(fields), "targetId": nilIfEmpty(targetID)}
	automationVars(vars, auto)
	if err := c.do(ctx, token, createQuery, vars, &out); err != nil {
		return nil, err
	}
	if out.Secret == nil {
		return nil, errors.New("gateway returned no secret")
	}
	return out.Secret, nil
}

const generateQuery = `mutation Generate($folderId:ID!,$typeId:ID!,$name:String!,$fields:[SecretFieldInput!]!,$policyId:ID,$targetId:ID,$returnValue:Boolean,$disableRotation:Boolean,$disableHeartbeat:Boolean,$keepFolder:Boolean){
  generateSecretForPrincipal(folderId:$folderId,typeId:$typeId,name:$name,fields:$fields,policyId:$policyId,targetId:$targetId,returnValue:$returnValue,disableRotation:$disableRotation,disableHeartbeat:$disableHeartbeat,keepFolder:$keepFolder){
    secret{` + summaryFields + placementFields + `} generatedValue
  }
}`

// GenerateSecret generates a policy-compliant password and stores the
// secret. The generated value is returned only when returnValue is true. At
// most one Automation is used. As with CreateSecret, the summary's Placement
// says where the gateway stored it and why.
func (c *Client) GenerateSecret(ctx context.Context, token, folderID, typeID, name string, fields []Field, policyID, targetID string, returnValue bool, auto ...Automation) (*SecretSummary, string, error) {
	var out struct {
		Generated *struct {
			Secret         *SecretSummary `json:"secret"`
			GeneratedValue *string        `json:"generatedValue"`
		} `json:"generateSecretForPrincipal"`
	}
	vars := map[string]any{
		"folderId": folderID, "typeId": typeID, "name": name,
		"fields": fieldsOrEmpty(fields), "policyId": nilIfEmpty(policyID),
		"targetId": nilIfEmpty(targetID), "returnValue": returnValue,
	}
	automationVars(vars, auto)
	if err := c.do(ctx, token, generateQuery, vars, &out); err != nil {
		return nil, "", err
	}
	if out.Generated == nil || out.Generated.Secret == nil {
		return nil, "", errors.New("gateway returned no secret")
	}
	val := ""
	if returnValue && out.Generated.GeneratedValue != nil {
		val = *out.Generated.GeneratedValue
	}
	return out.Generated.Secret, val, nil
}

const moveQuery = `mutation Move($id:ID!,$destFolderId:ID!){
  moveSecretForPrincipal(id:$id,destFolderId:$destFolderId){` + summaryFields + `}
}`

// MoveSecret moves a secret to another folder (RACI-Author on source and
// destination, audited by vault).
func (c *Client) MoveSecret(ctx context.Context, token, id, destFolderID string) (*SecretSummary, error) {
	var out struct {
		Secret *SecretSummary `json:"moveSecretForPrincipal"`
	}
	if err := c.do(ctx, token, moveQuery, map[string]any{"id": id, "destFolderId": destFolderID}, &out); err != nil {
		return nil, err
	}
	if out.Secret == nil {
		return nil, errors.New("gateway returned no secret")
	}
	return out.Secret, nil
}

// Mapping is one FieldMappingInput (old field key -> new field key).
type Mapping struct {
	From string `json:"from"`
	To   string `json:"to"`
}

const changeTypeQuery = `mutation ChangeType($id:ID!,$newTypeId:ID!,$fieldMapping:[FieldMappingInput!],$fields:[SecretFieldInput!]){
  changeSecretTypeForPrincipal(id:$id,newTypeId:$newTypeId,fieldMapping:$fieldMapping,fields:$fields){
    secret{` + summaryFields + `} fieldKeys movedToNotesKeys automation{rotation heartbeat target}
  }
}`

// TypeChangeAutomation is what a type change left the secret's rotation,
// heartbeat and target at (gateway TypeChangeAutomation enums).
type TypeChangeAutomation struct {
	Rotation  string `json:"rotation"`
	Heartbeat string `json:"heartbeat"`
	Target    string `json:"target"`
}

// TypeChange is the result of ChangeSecretType.
type TypeChange struct {
	Secret    *SecretSummary `json:"secret"`
	FieldKeys []string       `json:"fieldKeys"`
	// MovedToNotesKeys are old field keys (never values) appended to the new
	// type's notes field.
	MovedToNotesKeys []string             `json:"movedToNotesKeys"`
	Automation       TypeChangeAutomation `json:"automation"`
}

// ChangeSecretType changes a secret's type, re-keying its stored values per
// mapping. It returns the summary, the field keys now populated (never
// values), the old keys appended to notes and the resulting automation and
// target state.
func (c *Client) ChangeSecretType(ctx context.Context, token, id, newTypeID string, mapping []Mapping, fields []Field) (*TypeChange, error) {
	var out struct {
		Changed *TypeChange `json:"changeSecretTypeForPrincipal"`
	}
	vars := map[string]any{"id": id, "newTypeId": newTypeID, "fieldMapping": nil, "fields": nil}
	if len(mapping) > 0 {
		vars["fieldMapping"] = mapping
	}
	if len(fields) > 0 {
		vars["fields"] = fields
	}
	if err := c.do(ctx, token, changeTypeQuery, vars, &out); err != nil {
		return nil, err
	}
	if out.Changed == nil || out.Changed.Secret == nil {
		return nil, errors.New("gateway returned no secret")
	}
	if out.Changed.FieldKeys == nil {
		out.Changed.FieldKeys = []string{}
	}
	if out.Changed.MovedToNotesKeys == nil {
		out.Changed.MovedToNotesKeys = []string{}
	}
	return out.Changed, nil
}

// nilIfEmpty sends JSON null rather than "" for optional GraphQL arguments,
// so the gateway sees "absent" instead of "filter on the empty string".
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// fieldsOrEmpty guarantees a JSON array (never null) for the non-null
// [SecretFieldInput!]! argument.
func fieldsOrEmpty(f []Field) []Field {
	if f == nil {
		return []Field{}
	}
	return f
}

// SecretUse is a request to use one secret field for one exact command.
type SecretUse struct {
	ID            string   `json:"id"`
	SecretID      string   `json:"secretId"`
	SecretName    string   `json:"secretName"`
	FieldKey      string   `json:"fieldKey"`
	Argv          []string `json:"argv"`
	State         string   `json:"state"`
	ExpiresAtUnix int64    `json:"expiresAtUnix"`
	ApprovalURL   string   `json:"approvalUrl"`
	Reveal        bool     `json:"reveal"`
	RunID         string   `json:"runId"`
	// Confirm: nobody else can decide this use, so the token's person
	// confirms the task once in the browser.
	Confirm bool `json:"confirm"`
}

const secretUseFields = `id secretId secretName fieldKey argv state expiresAtUnix approvalUrl reveal runId confirm` // #nosec G101 -- a GraphQL field selection, not a credential

const prepareUseMutation = `mutation Prepare($secretId:ID!,$fieldKey:String!,$argv:[String!]!,$clientLabel:String,$runId:String,$purpose:String){
  prepareSecretUse(secretId:$secretId,fieldKey:$fieldKey,argv:$argv,clientLabel:$clientLabel,runId:$runId,purpose:$purpose){` + secretUseFields + `}
}`

// PrepareSecretUse asks for a use of fieldKey bound to exactly argv. At most
// one Run is used; its purpose is cleaned with CleanPurpose.
func (c *Client) PrepareSecretUse(ctx context.Context, token, secretID, fieldKey string, argv []string, clientLabel string, run ...Run) (SecretUse, error) {
	var out struct {
		Use SecretUse `json:"prepareSecretUse"`
	}
	vars := map[string]any{"secretId": secretID, "fieldKey": fieldKey, "argv": argv, "clientLabel": nilIfEmpty(clientLabel)}
	runVars(vars, run)
	err := c.do(ctx, token, prepareUseMutation, vars, &out)
	return out.Use, err
}

const prepareRevealMutation = `mutation PrepareReveal($secretId:ID!,$fieldKey:String!,$clientLabel:String,$reveal:Boolean,$runId:String,$purpose:String){
  prepareSecretUse(secretId:$secretId,fieldKey:$fieldKey,clientLabel:$clientLabel,reveal:$reveal,runId:$runId,purpose:$purpose){` + secretUseFields + `}
}`

// PrepareReveal asks for the value of fieldKey itself, for a secret whose
// approval level needs a decision. It names no command. At most one
// Run is used, as for PrepareSecretUse.
func (c *Client) PrepareReveal(ctx context.Context, token, secretID, fieldKey, clientLabel string, run ...Run) (SecretUse, error) {
	var out struct {
		Use SecretUse `json:"prepareSecretUse"`
	}
	vars := map[string]any{"secretId": secretID, "fieldKey": fieldKey, "clientLabel": nilIfEmpty(clientLabel), "reveal": true}
	runVars(vars, run)
	err := c.do(ctx, token, prepareRevealMutation, vars, &out)
	return out.Use, err
}

const secretUseQuery = `query Use($id:ID!){ secretUse(id:$id){` + secretUseFields + `} }`

// SecretUse reads the current state of a use this token prepared.
func (c *Client) SecretUse(ctx context.Context, token, id string) (SecretUse, error) {
	var out struct {
		Use SecretUse `json:"secretUse"`
	}
	err := c.do(ctx, token, secretUseQuery, map[string]any{"id": id}, &out)
	return out.Use, err
}

const redeemUseMutation = `mutation Redeem($id:ID!){ redeemSecretUse(id:$id){ value use{` + secretUseFields + `} } }`

// RedeemSecretUse takes the value of an approved use. It works once.
func (c *Client) RedeemSecretUse(ctx context.Context, token, id string) (string, SecretUse, error) {
	var out struct {
		Redeemed struct {
			Value string    `json:"value"`
			Use   SecretUse `json:"use"`
		} `json:"redeemSecretUse"`
	}
	err := c.do(ctx, token, redeemUseMutation, map[string]any{"id": id}, &out)
	return out.Redeemed.Value, out.Redeemed.Use, err
}

// Connection is a connection profile targets bind to.
type Connection struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	UseTLS      bool   `json:"useTls"`
	TargetCount int    `json:"targetCount"`
}

const connectionsQuery = `query{ connectionsForPrincipal{ id name protocol port useTls targetCount } }`

// ListConnections lists the connection profiles.
func (c *Client) ListConnections(ctx context.Context, token string) ([]Connection, error) {
	var out struct {
		Conns []Connection `json:"connectionsForPrincipal"`
	}
	if err := c.do(ctx, token, connectionsQuery, nil, &out); err != nil {
		return nil, err
	}
	if out.Conns == nil {
		out.Conns = []Connection{}
	}
	return out.Conns, nil
}

// Target is a system secrets are validated against or rotated on.
type Target struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Kind         string `json:"kind"`
	Domain       string `json:"domain"`
	Realm        string `json:"realm"`
	ConnectionID string `json:"connectionId"`
	Description  string `json:"description"`
	OwnerUserID  string `json:"ownerUserId"`
	SecretCount  int    `json:"secretCount"`
	// SSHHostKeys are the target's pinned SSH host keys (OpenSSH public keys).
	SSHHostKeys []string `json:"sshHostKeys"`
}

const targetFields = `id name hostname kind domain realm connectionId description ownerUserId secretCount sshHostKeys`

const targetsQuery = `query Targets($query:String,$connectionId:ID){
  targetsForPrincipal(query:$query,connectionId:$connectionId){` + targetFields + `}
}`

// ListTargets lists the targets the caller can see, optionally filtered.
func (c *Client) ListTargets(ctx context.Context, token, query, connectionID string) ([]Target, error) {
	var out struct {
		Targets []Target `json:"targetsForPrincipal"`
	}
	vars := map[string]any{"query": nilIfEmpty(query), "connectionId": nilIfEmpty(connectionID)}
	if err := c.do(ctx, token, targetsQuery, vars, &out); err != nil {
		return nil, err
	}
	if out.Targets == nil {
		out.Targets = []Target{}
	}
	return out.Targets, nil
}

// TargetInput creates a target (no ID) or updates one.
type TargetInput struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	Kind         string `json:"kind,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Realm        string `json:"realm,omitempty"`
	ConnectionID string `json:"connectionId"`
	Description  string `json:"description,omitempty"`
	// SSHHostKeys is the whole pin list. nil leaves the field out, so an
	// update keeps the target's pins; a pointer to an empty slice clears them.
	SSHHostKeys *[]string `json:"sshHostKeys,omitempty"`
}

const saveTargetMutation = `mutation Save($input:MachineTargetInput!){ saveTargetForPrincipal(input:$input){` + targetFields + `} }`

// SaveTarget creates or updates a target.
func (c *Client) SaveTarget(ctx context.Context, token string, in TargetInput) (Target, error) {
	var out struct {
		Target Target `json:"saveTargetForPrincipal"`
	}
	err := c.do(ctx, token, saveTargetMutation, map[string]any{"input": in}, &out)
	return out.Target, err
}

const setSecretTargetMutation = `mutation SetTarget($secretId:ID!,$targetId:ID){
  setSecretTargetForPrincipal(secretId:$secretId,targetId:$targetId){` + summaryFields + `}
}`

// SetSecretTarget attaches targetID to a secret, or detaches its target when
// targetID is empty.
func (c *Client) SetSecretTarget(ctx context.Context, token, secretID, targetID string) (SecretSummary, error) {
	var out struct {
		Secret SecretSummary `json:"setSecretTargetForPrincipal"`
	}
	err := c.do(ctx, token, setSecretTargetMutation, map[string]any{"secretId": secretID, "targetId": nilIfEmpty(targetID)}, &out)
	return out.Secret, err
}

// CheckStatus is the last credential check of a secret against its target.
type CheckStatus struct {
	Result        string `json:"result"`
	CheckedAtUnix int64  `json:"checkedAtUnix"`
	Detail        string `json:"detail"`
	Pending       bool   `json:"pending"`
}

const requestCheckMutation = `mutation Check($secretId:ID!){ requestSecretCheck(secretId:$secretId) }`

// RequestSecretCheck asks for the stored credential to be checked now; it
// returns the request time.
func (c *Client) RequestSecretCheck(ctx context.Context, token, secretID string) (int64, error) {
	var out struct {
		At int64 `json:"requestSecretCheck"`
	}
	err := c.do(ctx, token, requestCheckMutation, map[string]any{"secretId": secretID}, &out)
	return out.At, err
}

const checkStatusQuery = `query Status($secretId:ID!){ secretCheckStatus(secretId:$secretId){ result checkedAtUnix detail pending } }`

// SecretCheckStatus reads the secret's last credential check.
func (c *Client) SecretCheckStatus(ctx context.Context, token, secretID string) (CheckStatus, error) {
	var out struct {
		Status CheckStatus `json:"secretCheckStatus"`
	}
	err := c.do(ctx, token, checkStatusQuery, map[string]any{"secretId": secretID}, &out)
	return out.Status, err
}
