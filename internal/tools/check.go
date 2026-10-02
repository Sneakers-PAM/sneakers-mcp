// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

const (
	toolTestSecret = "sneakers_test_secret"
	// A connector polls for due checks every few seconds; waiting well past
	// that covers a busy queue without holding a tool call open for minutes.
	defaultCheckPoll = 2 * time.Second
	defaultCheckWait = 45 * time.Second
)

type testSecretIn struct {
	SecretID string `json:"secretId"`
}
type testSecretOut struct {
	Result        string `json:"result,omitempty" jsonschema:"ok, failed, unreachable or unknown"`
	Detail        string `json:"detail,omitempty" jsonschema:"the connector's reason; never a secret value"`
	CheckedAtUnix int64  `json:"checkedAtUnix,omitempty"`
	Pending       bool   `json:"pending"`
	Available     *bool  `json:"available,omitempty" jsonschema:"false when no connector can serve checks in this environment"`
	Message       string `json:"message,omitempty"`
}

func checkOut(st gwclient.CheckStatus) testSecretOut {
	return testSecretOut{Result: strings.ToLower(st.Result), Detail: st.Detail, CheckedAtUnix: st.CheckedAtUnix}
}

func (t *toolset) testSecret(ctx context.Context, req *mcp.CallToolRequest, in testSecretIn) (*mcp.CallToolResult, testSecretOut, error) {
	var out testSecretOut
	err := t.run(req, toolTestSecret, func() error { return checkLen("secretId", in.SecretID, maxIDLen, true) },
		func(token string) error {
			at, err := t.gw.RequestSecretCheck(ctx, token, in.SecretID)
			if isNoConnector(err) {
				out = testSecretOut{Available: ptr(false), Message: noConnectorMessage}
				return nil
			}
			if isRateLimited(err) {
				out, err = t.latestCheck(ctx, token, in.SecretID)
				return err
			}
			if err != nil {
				return err
			}
			out, err = t.awaitCheck(ctx, token, in.SecretID, at)
			return err
		})
	if err != nil {
		return nil, testSecretOut{}, err
	}
	return nil, out, nil
}

const noConnectorMessage = "No connector is available in this environment, so this credential can't be checked right now."

// isNoConnector matches the vault's refusal when no connector could ever pick
// the check up, so polling would only wait out the full timeout.
func isNoConnector(err error) bool {
	var ge *gwclient.GraphQLError
	return errors.As(err, &ge) && strings.Contains(ge.Error(), "no connector is available in this environment")
}

// isRateLimited matches the vault's per-secret check limit by its gRPC code,
// which the gateway relays as "rpc error: code = <Code> desc = <text>"; the
// text after desc is free to change.
func isRateLimited(err error) bool {
	var ge *gwclient.GraphQLError
	if !errors.As(err, &ge) {
		return false
	}
	for _, m := range ge.Messages {
		if grpcCode(m) == "ResourceExhausted" {
			return true
		}
	}
	return false
}

// grpcCode returns the code name from a relayed gRPC status message, or ""
// when the message isn't one.
func grpcCode(msg string) string {
	_, rest, ok := strings.Cut(msg, "rpc error: code = ")
	if !ok {
		return ""
	}
	code, _, _ := strings.Cut(rest, " ")
	return code
}

func (t *toolset) latestCheck(ctx context.Context, token, secretID string) (testSecretOut, error) {
	st, err := t.gw.SecretCheckStatus(ctx, token, secretID)
	out := checkOut(st)
	out.Pending = st.Pending
	out.Message = "a check was already requested in the last minute; this is the latest result"
	return out, err
}

// awaitCheck polls until a result newer than the request is reported, or the
// wait runs out.
func (t *toolset) awaitCheck(ctx context.Context, token, secretID string, requestedAt int64) (testSecretOut, error) {
	poll, wait := t.checkPoll, t.checkWait
	if poll == 0 {
		poll = defaultCheckPoll
	}
	if wait == 0 {
		wait = defaultCheckWait
	}
	deadline := time.Now().Add(wait)
	for {
		st, err := t.gw.SecretCheckStatus(ctx, token, secretID)
		if err != nil {
			return testSecretOut{}, err
		}
		if !st.Pending && st.CheckedAtUnix >= requestedAt {
			return checkOut(st), nil
		}
		if time.Now().After(deadline) {
			return testSecretOut{Pending: true, Message: "no connector has reported yet; the check stays queued, so call again in a minute to read the result"}, nil
		}
		select {
		case <-ctx.Done():
			return testSecretOut{}, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func registerCheckTool(s *mcp.Server, t *toolset) {
	mcp.AddTool(s, &mcp.Tool{
		Name: toolTestSecret,
		Description: "Check a secret's stored credential against its target now, through the Sneakers connector, and " +
			"return ok, failed (with the reason) or unreachable. Never returns a value. The secret needs a " +
			"heartbeat-capable type and a target; at most one check a minute per secret. When no connector is " +
			"available in this environment it returns available=false with a message instead of checking.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
	}, t.testSecret)
}
