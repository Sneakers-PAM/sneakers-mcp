// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

type fakeGW struct {
	*httptest.Server
	auth  atomic.Value
	calls atomic.Int32
	vars  atomic.Value
}

func fakeGateway(t *testing.T, body string) *fakeGW {
	t.Helper()
	f := &fakeGW{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.auth.Store(r.Header.Get("Authorization"))
		var req struct {
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.vars.Store(req.Variables)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGW) gotAuth() string {
	s, _ := f.auth.Load().(string)
	return s
}

// callReq builds a CallToolRequest the way the Streamable HTTP transport
// populates Extra for a call that passed the bearer middleware: the inbound
// header plus the verified TokenInfo.
func callReq(bearer string) *mcp.CallToolRequest {
	h := http.Header{}
	h.Set("Authorization", bearer)
	return &mcp.CallToolRequest{Extra: &mcp.RequestExtra{
		Header:    h,
		TokenInfo: &auth.TokenInfo{UserID: "client-abc", Expiration: time.Now().Add(time.Hour)},
	}}
}

func newTools(gwURL string, logBuf *bytes.Buffer) *toolset {
	lg := zerolog.Nop()
	if logBuf != nil {
		lg = zerolog.New(logBuf)
	}
	return &toolset{gw: gwclient.New(gwURL, nil), log: lg}
}

func TestGetSecretForwardsCallerTokenAndReturnsValue(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"revealSecretFieldForPrincipal":"hunter2"}}`)

	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer agent-tok"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Value != "hunter2" {
		t.Fatalf("Value = %q, want \"hunter2\"", out.Value)
	}
	if gw.gotAuth() != "Bearer agent-tok" {
		t.Fatalf("gateway saw Authorization %q, want the caller's token forwarded", gw.gotAuth())
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"revealSecretFieldForPrincipal":"v"}}`)
	if _, _, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("bearer agent-tok"), getSecretIn{ID: "s1", FieldKey: "password"}); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if gw.gotAuth() != "Bearer agent-tok" {
		t.Fatalf("gateway saw %q", gw.gotAuth())
	}
}

func TestUnauthenticatedCallsNeverReachGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"revealSecretFieldForPrincipal":"leaked"}}`)
	ts := newTools(gw.URL, nil)

	noTokenInfo := callReq("Bearer agent-tok")
	noTokenInfo.Extra.TokenInfo = nil

	cases := map[string]*mcp.CallToolRequest{
		"nil request":           nil,
		"no extra":              {},
		"no header":             {Extra: &mcp.RequestExtra{TokenInfo: &auth.TokenInfo{UserID: "x"}}},
		"not bearer":            callReq("Basic Zm9vOmJhcg=="),
		"bearer without token":  callReq("Bearer"),
		"verified info missing": noTokenInfo,
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			_, out, err := ts.getSecret(context.Background(), req, getSecretIn{ID: "s1", FieldKey: "password"})
			if err == nil || out.Value != "" {
				t.Fatalf("want rejection, got value=%q err=%v", out.Value, err)
			}
		})
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway was called %d times without an authenticated caller", gw.calls.Load())
	}
}

func TestRACIDenialSurfacesAsToolError(t *testing.T) {
	gw := fakeGateway(t, `{"data":null,"errors":[{"message":"not permitted to read this secret"}]}`)

	_, out, err := newTools(gw.URL, nil).getSecret(context.Background(), callReq("Bearer t"), getSecretIn{ID: "s1", FieldKey: "password"})
	if err == nil {
		t.Fatal("a gateway permission error must surface as a tool error, never an empty success")
	}
	if out.Value != "" {
		t.Fatalf("no value may be returned on denial, got %q", out.Value)
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("error should carry the gateway message, got: %v", err)
	}
}

func TestGatewayUnauthorizedBecomesClearToolError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	_, _, err := newTools(srv.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{})
	if err == nil || !strings.Contains(err.Error(), "rejected the caller's credentials") {
		t.Fatalf("err = %v, want a credentials-rejected tool error", err)
	}
}

func TestFindSecretsMapsSummaries(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"findSecretsForPrincipal":[{"id":"s1","name":"n1","folderId":"f1","typeId":"t1","targetId":"tg"}]}}`)

	_, out, err := newTools(gw.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{Query: "n"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if len(out.Secrets) != 1 || out.Secrets[0].ID != "s1" || out.Secrets[0].TargetID != "tg" {
		t.Fatalf("Secrets = %+v, want one summary s1/tg", out.Secrets)
	}
}

func TestFindSecretsEmptyIsAnEmptyListNotNull(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"findSecretsForPrincipal":[]}}`)
	_, out, err := newTools(gw.URL, nil).findSecrets(context.Background(), callReq("Bearer t"), findSecretsIn{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if string(b) != `{"secrets":[]}` {
		t.Fatalf("marshalled = %s", b)
	}
}

func TestCreateSecretPassesFields(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"createSecretForPrincipal":{"id":"s2","name":"svc","folderId":"f","typeId":"t"}}}`)

	in := createSecretIn{FolderID: "f", TypeID: "t", Name: "svc", Fields: []fieldIn{{Key: "username", Value: "u"}, {Key: "password", Value: "p"}}}
	_, out, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"), in)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.Secret.ID != "s2" {
		t.Fatalf("Secret = %+v", out.Secret)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if fs, _ := vars["fields"].([]any); len(fs) != 2 {
		t.Fatalf("fields forwarded = %#v", vars["fields"])
	}
}

func TestGenerateSecretReturnsValueOnlyWhenAsked(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"generateSecretForPrincipal":{"secret":{"id":"s9","name":"svc","folderId":"f","typeId":"t"},"generatedValue":null}}}`)

	_, out, err := newTools(gw.URL, nil).generateSecret(context.Background(), callReq("Bearer t"), generateSecretIn{FolderID: "f", TypeID: "t", Name: "svc"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out.GeneratedValue != "" {
		t.Fatalf("GeneratedValue = %q, want empty when returnValue was not requested", out.GeneratedValue)
	}
	if out.Secret.ID != "s9" {
		t.Fatalf("Secret.ID = %q, want s9", out.Secret.ID)
	}
	vars, _ := gw.vars.Load().(map[string]any)
	if vars["returnValue"] != false {
		t.Fatalf("returnValue forwarded = %v, want false by default", vars["returnValue"])
	}
}

func TestInputLimitsRejectBeforeCallingGateway(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	ts := newTools(gw.URL, nil)
	ctx := context.Background()
	long := func(n int) string { return strings.Repeat("x", n) }
	manyFields := make([]fieldIn, maxFields+1)
	for i := range manyFields {
		manyFields[i] = fieldIn{Key: "k" + strings.Repeat("x", i), Value: "v"}
	}

	checks := map[string]func() error{
		"find: query too long": func() error {
			_, _, err := ts.findSecrets(ctx, callReq("Bearer t"), findSecretsIn{Query: long(maxQueryLen + 1)})
			return err
		},
		"find: folder too long": func() error {
			_, _, err := ts.findSecrets(ctx, callReq("Bearer t"), findSecretsIn{FolderID: long(maxIDLen + 1)})
			return err
		},
		"get: id missing": func() error {
			_, _, err := ts.getSecret(ctx, callReq("Bearer t"), getSecretIn{FieldKey: "p"})
			return err
		},
		"get: field missing": func() error { _, _, err := ts.getSecret(ctx, callReq("Bearer t"), getSecretIn{ID: "s"}); return err },
		"get: id too long": func() error {
			_, _, err := ts.getSecret(ctx, callReq("Bearer t"), getSecretIn{ID: long(maxIDLen + 1), FieldKey: "p"})
			return err
		},
		"create: name missing": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t"})
			return err
		},
		"create: name too long": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t", Name: long(maxNameLen + 1)})
			return err
		},
		"create: too many fields": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t", Name: "n", Fields: manyFields})
			return err
		},
		"create: value too long": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t", Name: "n", Fields: []fieldIn{{Key: "k", Value: long(maxFieldValueLen + 1)}}})
			return err
		},
		"create: empty key": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t", Name: "n", Fields: []fieldIn{{Key: "", Value: "v"}}})
			return err
		},
		"create: duplicate key": func() error {
			_, _, err := ts.createSecret(ctx, callReq("Bearer t"), createSecretIn{FolderID: "f", TypeID: "t", Name: "n", Fields: []fieldIn{{Key: "k", Value: "a"}, {Key: "k", Value: "b"}}})
			return err
		},
		"generate: folder missing": func() error {
			_, _, err := ts.generateSecret(ctx, callReq("Bearer t"), generateSecretIn{TypeID: "t", Name: "n"})
			return err
		},
		"generate: policy too long": func() error {
			_, _, err := ts.generateSecret(ctx, callReq("Bearer t"), generateSecretIn{FolderID: "f", TypeID: "t", Name: "n", PolicyID: long(maxIDLen + 1)})
			return err
		},
	}
	for name, fn := range checks {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("want validation error")
			}
		})
	}
	if gw.calls.Load() != 0 {
		t.Fatalf("gateway called %d times for invalid input", gw.calls.Load())
	}
}

func TestValidationErrorsDoNotEchoFieldValues(t *testing.T) {
	gw := fakeGateway(t, `{"data":{}}`)
	secret := "S3CRET-" + strings.Repeat("z", maxFieldValueLen)
	_, _, err := newTools(gw.URL, nil).createSecret(context.Background(), callReq("Bearer t"),
		createSecretIn{FolderID: "f", TypeID: "t", Name: "n", Fields: []fieldIn{{Key: "password", Value: secret}}})
	if err == nil || strings.Contains(err.Error(), "S3CRET") {
		t.Fatalf("err = %v; must fail without echoing the value", err)
	}
}

func TestLogsCarrySubjectButNeverTokensOrValues(t *testing.T) {
	gw := fakeGateway(t, `{"data":{"generateSecretForPrincipal":{"secret":{"id":"s9","name":"svc","folderId":"f","typeId":"t"},"generatedValue":"GENERATED-PW"}}}`)
	var buf bytes.Buffer
	ts := newTools(gw.URL, &buf)

	_, out, err := ts.generateSecret(context.Background(), callReq("Bearer TOKEN-MARKER"),
		generateSecretIn{FolderID: "f", TypeID: "t", Name: "svc", ReturnValue: true, Fields: []fieldIn{{Key: "username", Value: "FIELD-MARKER"}}})
	if err != nil || out.GeneratedValue != "GENERATED-PW" {
		t.Fatalf("handler: %v / %q", err, out.GeneratedValue)
	}
	gw2 := fakeGateway(t, `{"data":{"revealSecretFieldForPrincipal":"REVEALED-MARKER"}}`)
	ts.gw = gwclient.New(gw2.URL, nil)
	if _, _, err := ts.getSecret(context.Background(), callReq("Bearer TOKEN-MARKER"), getSecretIn{ID: "s", FieldKey: "password"}); err != nil {
		t.Fatal(err)
	}

	logs := buf.String()
	if !strings.Contains(logs, "client-abc") || !strings.Contains(logs, "sneakers_generate_secret") {
		t.Fatalf("expected an audit line with subject and tool name, got: %s", logs)
	}
	for _, leak := range []string{"TOKEN-MARKER", "GENERATED-PW", "FIELD-MARKER", "REVEALED-MARKER"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log output leaks %s: %s", leak, logs)
		}
	}
}

// listRegisteredTools registers the toolset on a fresh server and lists it
// through a real in-memory MCP client session.
func listRegisteredTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	Register(s, gwclient.New("http://unused", nil), zerolog.Nop())

	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

func TestRegisterExposesExactlyTheNineteenTools(t *testing.T) {
	var names []string
	readOnly := map[string]bool{}
	for _, tl := range listRegisteredTools(t) {
		names = append(names, tl.Name)
		readOnly[tl.Name] = tl.Annotations != nil && tl.Annotations.ReadOnlyHint
	}
	slices.Sort(names)
	want := []string{"sneakers_change_secret_type", "sneakers_create_folder", "sneakers_create_secret", "sneakers_find_secrets", "sneakers_generate_secret",
		"sneakers_get_secret", "sneakers_list_connections", "sneakers_list_folders", "sneakers_list_secret_types", "sneakers_list_targets",
		"sneakers_move_secret", "sneakers_redeem_reveal", "sneakers_rename_folder", "sneakers_rename_secret", "sneakers_save_target",
		"sneakers_set_secret_automation", "sneakers_set_secret_target", "sneakers_test_secret", "sneakers_update_secret"}
	if !slices.Equal(names, want) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
	wantReadOnly := map[string]bool{
		"sneakers_find_secrets": true, "sneakers_get_secret": true, "sneakers_list_folders": true, "sneakers_list_secret_types": true,
		"sneakers_list_connections": true, "sneakers_list_targets": true,
		"sneakers_create_secret": false, "sneakers_generate_secret": false, "sneakers_save_target": false, "sneakers_set_secret_target": false,
		"sneakers_rename_secret": false, "sneakers_create_folder": false, "sneakers_rename_folder": false,
		"sneakers_set_secret_automation": false, "sneakers_update_secret": false,
	}
	for name, want := range wantReadOnly {
		if readOnly[name] != want {
			t.Fatalf("readOnly hints wrong: %v", readOnly)
		}
	}
}

// Move and change-type alter who can reach a secret / how its fields are
// keyed, so they must be flagged destructive and say so to the agent.
func TestMoveAndChangeTypeAreFlaggedDestructive(t *testing.T) {
	seen := 0
	for _, tl := range listRegisteredTools(t) {
		if tl.Name != "sneakers_move_secret" && tl.Name != "sneakers_change_secret_type" {
			continue
		}
		seen++
		a := tl.Annotations
		if a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint || a.IdempotentHint {
			t.Fatalf("%s annotations wrong: %+v", tl.Name, a)
		}
		if !strings.Contains(tl.Description, "WARNING") || !strings.Contains(strings.ToLower(tl.Description), "audited") {
			t.Fatalf("%s description must warn about its effects and auditing: %q", tl.Name, tl.Description)
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 mutating tools", seen)
	}
}
