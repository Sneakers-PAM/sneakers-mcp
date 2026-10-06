// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gwclient

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Run groups the uses one agent run raises, so they're decided or confirmed on
// one page. ID is a grouping hint, not an authority; Purpose is the agent's
// own words for its task, shown on that page as plain text.
type Run struct {
	ID      string
	Purpose string
}

// MaxPurposeRunes is the longest purpose vault accepts.
const MaxPurposeRunes = 200

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidRunID reports whether id has the shape vault accepts.
func ValidRunID(id string) bool { return runIDPattern.MatchString(id) }

// NewRunID returns a fresh run id: "run_" and 128 random bits in base32.
func NewRunID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return "run_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// CleanPurpose turns free task text into the one line of plain text vault
// accepts: invalid UTF-8 and control characters are dropped, whitespace runs
// become one space, and the result is cut to MaxPurposeRunes.
func CleanPurpose(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > MaxPurposeRunes {
		s = strings.TrimSpace(string([]rune(s)[:MaxPurposeRunes]))
	}
	return s
}

// runVars adds the run id and purpose to a prepare call. Unset values are
// sent as null.
func runVars(vars map[string]any, run []Run) {
	var r Run
	if len(run) > 0 {
		r = run[0]
	}
	vars["runId"], vars["purpose"] = nilIfEmpty(r.ID), nilIfEmpty(CleanPurpose(r.Purpose))
}

const secretUseRunQuery = `query Run($runId:String!){ secretUseRun(runId:$runId){` + secretUseFields + `} }`

// SecretUseRun lists this token's own pending uses in one run.
func (c *Client) SecretUseRun(ctx context.Context, token, runID string) ([]SecretUse, error) {
	var out struct {
		Uses []SecretUse `json:"secretUseRun"`
	}
	if err := c.do(ctx, token, secretUseRunQuery, map[string]any{"runId": runID}, &out); err != nil {
		return nil, err
	}
	if out.Uses == nil {
		out.Uses = []SecretUse{}
	}
	return out.Uses, nil
}
