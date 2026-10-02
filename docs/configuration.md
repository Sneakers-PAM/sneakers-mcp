# Configuration

The MCP server reads its settings from the environment at start. A setting it can't use stops it
with a fatal log line and a non-zero exit.

## Settings

| Variable | Default | Notes |
|---|---|---|
| `HTTP_PORT` | `9101` | HTTP listen port for `/mcp`, `/health` and the metadata routes. |
| `GATEWAY_MACHINE_GRAPHQL_URL` | `http://sneakers-gateway:9100/machine/graphql` | The gateway's machine GraphQL endpoint, used for every tool call and for the token pre-check. |
| `MCP_ACCEPT_API_TOKENS` | `true` | Accept service-account API tokens and personal tokens, which the gateway confirms. Must parse as a boolean. |
| `HYDRA_ISSUER` | (empty: Ory Hydra mode off) | The exact `iss` string of the Ory Hydra tokens, for example `https://hydra.example.org/` (the trailing slash matters). Setting it turns the JWT mode on. |
| `HYDRA_JWKS_URL` | `http://sneakers-hydra:4444/.well-known/jwks.json` | Where the signing keys are fetched from. |
| `HYDRA_AUDIENCE` | `sneakers-mcp` | The required `aud`. Must match the gateway's `HYDRA_AUDIENCE`. |
| `MCP_RESOURCE_URL` | (none) | This server's public URL, for example `https://sneakers-mcp.example.org/mcp`. Advertised in the protected-resource metadata. Required when `HYDRA_ISSUER` is set; without it no metadata is served. |
| `MCP_AUTHORIZATION_SERVER` | (none) | The Sneakers sign-in issuer (the gateway's OAuth server on the UI host, for example `https://sneakers.example.org`). Advertised as the authorization server, so OAuth-capable MCP clients can sign the user in and receive a personal token. Without it, Ory Hydra mode advertises `HYDRA_ISSUER`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OTLP gRPC collector (`host:port`) for metrics and traces. |
| `SERVICE_VERSION` | the build stamp (`dev` when unstamped) | Reported as the version in MCP `serverInfo`. |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT` | `json` | `json` for clusters; `console` for local development. |

The server refuses to start when:

- `MCP_ACCEPT_API_TOKENS` is `false` and `HYDRA_ISSUER` is empty (no bearer mode at all);
- `MCP_ACCEPT_API_TOKENS` is not a boolean;
- `HYDRA_ISSUER` is set without `MCP_RESOURCE_URL`, or `MCP_RESOURCE_URL` isn't an absolute URL.

## Bearer modes

Each bearer is classified by its shape alone and goes to exactly one check. Anything else gets a
bare `401 invalid token`; the reason goes to the log, never to the caller.

| Bearer shape | Check | On when |
|---|---|---|
| A JWT: three base64url segments, header `alg` = `RS256` | Ory Hydra: signature against the JWKS, `iss`, `aud` and `exp`, checked locally | `HYDRA_ISSUER` is set |
| A service-account API token: exactly 43 characters of canonical unpadded base64url (32 bytes) | The gateway: `query{machineHealth machineWhoami{...}}` sent to `/machine/graphql` with the caller's bearer | `MCP_ACCEPT_API_TOKENS=true` |
| A personal token: `snk_u_` followed by the same 43-character body, issued at `/login` | The same gateway check; the gateway acts as the token's owner with their live groups | `MCP_ACCEPT_API_TOKENS=true` |

The MCP server can't verify an opaque token itself, so it asks the gateway before it handles any MCP
request. A bad token gets a `401` here and never reaches a tool. A positive answer is cached for 30
seconds (the hard cap is 60), keyed only by the SHA-256 of the token; the raw token is never stored
or logged. Revocation still applies to data at once, because the gateway checks the token again on
every tool call: the cache only lets an admitted token reach `initialize` and `tools/list` for up to
30 seconds more. A gateway `401` or `403` means reject. A gateway error, an unreachable gateway or an
unexpected answer all fail closed (`401`) and are never cached.

Logs name a token caller as `sa-token:<owner or account id>:<12 hex of its SHA-256>` or
`user-token:<user id>:<12 hex>`, and an Ory Hydra caller by its `sub`.

For a deployment without Ory Hydra, leave `HYDRA_ISSUER` empty and `MCP_ACCEPT_API_TOKENS` at its
default; any JWT-shaped bearer is then refused.

## Local development

```bash
LOG_LEVEL=trace LOG_FORMAT=console \
GATEWAY_MACHINE_GRAPHQL_URL=http://localhost:9100/machine/graphql \
go run ./cmd/mcp
```

The server starts and serves without a collector on `localhost:4317`; only the telemetry export
fails.
