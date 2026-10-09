# AGENTS.md - sneakers-mcp

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers MCP server: the bridge that lets AI agents use the vault over MCP (Streamable HTTP,
stateless), plus two local commands for people, `sneakers-run` and `sneakers-put`. A leaf HTTP
service with no database: it checks each caller's bearer (Ory Hydra JWTs locally, API and personal
tokens through the gateway) and turns every tool call into one or more calls to the gateway's
`/machine/graphql` with that same token. Before changing it, know the rules it keeps: it holds no
credentials and makes no access decisions (the gateway and vault do); every bearer check fails
closed with a bare `401`; tokens, tool arguments and secret values are never logged; values that
already exist on disk go through `sneakers-put`, never through a tool call; and nothing in it may
reach the SSH broker service.

## Layout

- `cmd/mcp/` - the server entrypoint: environment, the bearer modes, the routes and the
  protected-resource metadata.
- `cmd/sneakers-run/`, `cmd/sneakers-put/` - the two local commands.
- `internal/authn/` - classifies a bearer by shape and confirms API and personal tokens with the
  gateway, with a short positive cache keyed by the token's SHA-256.
- `internal/hydra/` - the Ory Hydra JWT verifier (JWKS fetch and cache).
- `internal/tools/` - the MCP tools; each is a thin mapping onto the gateway client.
- `internal/gwclient/` - the machine GraphQL client; every call takes the caller's token.
- `internal/cliauth/` - the token and URL rules both commands share.
- `internal/secretrun/`, `internal/secretput/` - the logic behind the two commands.
- `scripts/cli-dist.sh` - cross-builds the commands into `dist/`.
- `docs/` - configuration, API, runbook and the command pages.

## Build, test, lint

- Build: `task build`
- Test: `task test`; the gateway and the JWKS are `httptest` servers, so nothing else is needed.
- Lint: `task lint`.
- Gateway contract: `internal/contract` checks every GraphQL operation against the gateway's
  machine schema, vendored at the commit in `gateway-schema.env`; bump the ref and run
  `scripts/gateway-schema-fetch.sh` when the gateway's schema changes (docs/api.md, "Gateway
  contract").
- Commands: `./scripts/cli-dist.sh` builds both for linux and darwin, amd64 and arm64.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names.
- The contract with the gateway is its machine GraphQL schema in `Sneakers-PAM/sneakers-gateway`
  (`graphql/machine.graphqls`); there is no Go dependency on it. A new tool needs the matching
  field there first.
- Match gateway errors on the gRPC code inside the message (`rpc error: code = <Code> desc = ...`),
  never on the words after `desc =`, which the services may reword.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`.
