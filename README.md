# MCP Server 🤖

> 🧭 Lets AI agents use the Sneakers vault over the Model Context Protocol, with each caller's own token, plus the sneakers-run and sneakers-put commands for people.

The MCP server is a thin, stateless bridge. It speaks MCP over Streamable HTTP (stateless mode) at
`/mcp`, checks each caller's bearer token, and forwards every tool call to the gateway's
`/machine/graphql` carrying that same caller's token, unchanged. It holds no credentials of its own,
no state and no authorization logic: the gateway resolves the token to its user or service account,
and the vault applies RACI and writes the audit trail.

## ✨ Highlights

- 🔐 **Fail-closed bearer gate:** Ory Hydra client-credentials JWTs are checked locally against the JWKS; service-account and personal tokens are confirmed by the gateway. Anything else is a bare `401`.
- 🧰 **Tools for agents:** find, read and reveal secrets (with owner approval when the secret asks for it), create, generate, move, rename and retype them, organise folders, manage targets and turn rotation and heartbeat on or off.
- 🙈 **Values stay out of transcripts:** tool descriptions send agents to `sneakers-put` for any value that already exists on disk, and refuse sensitive fields in updates.
- 🏃 **sneakers-run:** runs one command with a secret supplied on stdin or in a private temp file, released only for the exact command its owner approved, and masked in the output.
- 📥 **sneakers-put:** creates or updates a secret from files or stdin, so a value never passes through an agent session or the shell history.
- 📈 **Observable:** OpenTelemetry metrics, and one JSON log line per request and per tool call, never with tokens, arguments or values.

## ⚠️ Before production

The MCP server trusts nothing it can't check, but it is only as private as the gateway behind it.
Serve `/mcp` over HTTPS, keep the gateway hop on a private network, and read
[docs/runbook.md](docs/runbook.md) before you deploy it.

## 🚀 Run it

```bash
GATEWAY_MACHINE_GRAPHQL_URL=http://localhost:9100/machine/graphql go run ./cmd/mcp
```

HTTP listens on port 9101. With no other settings only service-account and personal tokens are
accepted, and the gateway confirms each one. [docs/configuration.md](docs/configuration.md) lists
every setting, including the Ory Hydra JWT mode.

Run the tests (the gateway and the JWKS are test HTTP servers, so nothing else is needed):

```bash
go test ./...
```

## 💻 The local commands

Install them with Go, or cross-build them all into `dist/` with `scripts/cli-dist.sh`:

```bash
go install github.com/Sneakers-PAM/sneakers-mcp/cmd/sneakers-run@latest
go install github.com/Sneakers-PAM/sneakers-mcp/cmd/sneakers-put@latest
```

Both need `SNEAKERS_URL` (your Sneakers base URL, `https://` only) and `SNEAKERS_TOKEN` (a personal
token from `/login`, `snk_u_...`):

```bash
export SNEAKERS_URL=https://sneakers.example.org SNEAKERS_TOKEN=snk_u_...
sneakers-run -secret <id> -- ssh admin@router-01
sneakers-put -id <secret id> -field password=@./new.pw
```

See [docs/sneakers-run.md](docs/sneakers-run.md) and [docs/sneakers-put.md](docs/sneakers-put.md).

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables and the bearer modes.
- [docs/api.md](docs/api.md): the HTTP routes, the tools and client setup.
- [docs/runbook.md](docs/runbook.md): operating the service.
- [docs/sneakers-run.md](docs/sneakers-run.md), [docs/sneakers-put.md](docs/sneakers-put.md) and [docs/sneakers-update-secret.md](docs/sneakers-update-secret.md).

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
