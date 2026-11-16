// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"

	"github.com/Sneakers-PAM/sneakers-mcp/internal/gwclient"
)

// DisabledSetting is the environment variable that turns single MCP functions
// off. A refusal names it so the operator knows where to look.
const DisabledSetting = "MCP_DISABLED_TOOLS"

// Names returns every tool name Register adds, sorted.
func Names() []string {
	s := mcp.NewServer(&mcp.Implementation{Name: "names", Version: "0"}, nil)
	Register(s, gwclient.New("http://unused", nil), zerolog.Nop())
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		return nil
	}
	defer func() { _ = ss.Close() }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "names", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	return names
}

// ParseDisabled reads a comma-separated list of tool names. Blanks are
// skipped. A name that is not a tool is an error naming it, so a typo can't
// leave a function on that the operator meant to turn off.
func ParseDisabled(csv string) ([]string, error) {
	known := Names()
	var out []string
	for _, n := range strings.Split(csv, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !slices.Contains(known, n) {
			return nil, fmt.Errorf("%s names %q, which is not an MCP function", DisabledSetting, n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// Restrict turns the named tools off on s for good (the static list).
func Restrict(s *mcp.Server, disabled []string, log zerolog.Logger) {
	if len(disabled) == 0 {
		return
	}
	RestrictWith(s, NewSwitches(disabled, nil, 0, log), log)
}

// RestrictWith turns tools off on s as sw decides, per call, in the server
// rather than the page: tools/list leaves them out and tools/call refuses
// them, naming the setting, before anything reaches the gateway.
func RestrictWith(s *mcp.Server, sw *Switches, log zerolog.Logger) {
	log.Info().Int("static", len(sw.static)).Bool("from_gateway", sw.fetch != nil).Msg("mcp functions can be turned off")
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" && method != "tools/list" {
				return next(ctx, method, req)
			}
			off := sw.Off(ctx, bearerOf(req))
			if r, ok := req.(*mcp.CallToolRequest); ok && method == "tools/call" && r.Params != nil && off[r.Params.Name] {
				log.Warn().Str("tool", r.Params.Name).Msg("mcp call refused: function is turned off")
				return &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s is turned off on this install (setting %s)", r.Params.Name, DisabledSetting)}},
				}, nil
			}
			res, err := next(ctx, method, req)
			if lr, ok := res.(*mcp.ListToolsResult); ok && method == "tools/list" && err == nil {
				lr.Tools = withoutOff(lr.Tools, off)
			}
			return res, err
		}
	})
}

func withoutOff(in []*mcp.Tool, off map[string]bool) []*mcp.Tool {
	kept := make([]*mcp.Tool, 0, len(in))
	for _, tl := range in {
		if !off[tl.Name] {
			kept = append(kept, tl)
		}
	}
	return kept
}
