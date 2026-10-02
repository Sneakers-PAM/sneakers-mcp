# Contributing to sneakers-mcp

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). The gateway and the Ory Hydra JWKS are `httptest`
  servers inside the tests, so `go test ./...` needs nothing else running.
- Adding or changing a tool: the gateway's machine GraphQL schema is the contract. The field must
  exist in `graphql/machine.graphqls` in
  [sneakers-gateway](https://github.com/Sneakers-PAM/sneakers-gateway) first; then add the
  operation to `internal/gwclient` and the tool to `internal/tools`, with tests for both, and
  update [docs/api.md](docs/api.md).
- Values that already exist on disk never go through a tool call; point agents at `sneakers-put`
  instead. No tool may reach the SSH broker service.
- Every `.go` file starts with the Apache-2.0 header:
  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```
- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
- Never log tokens, tool arguments or secret values, not even at `trace`; log an opaque id instead.
