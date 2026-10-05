# Runbook

## Before you deploy

- **Serve `/mcp` over HTTPS.** Every request carries a bearer token, and tool results can carry
  secret values. Terminate TLS in front of the server and set `MCP_RESOURCE_URL` to the public
  `https://` URL.
- **Keep the gateway hop private.** The server sends each caller's token to
  `GATEWAY_MACHINE_GRAPHQL_URL`. Use a private network or `https://` for it; redirects from it are
  never followed, so a token can't be replayed to another URL.
- **Pick the bearer modes on purpose.** API and personal tokens are on by default. Set
  `HYDRA_ISSUER` (with `MCP_RESOURCE_URL`) only if agents get client-credentials JWTs from Ory Hydra,
  and make `HYDRA_AUDIENCE` match the gateway's.
- **Allow long requests.** `sneakers_test_secret` can hold a call open for up to 45 seconds while
  it waits for a connector; the server's write timeout is 90 seconds. A proxy in front needs a read
  timeout above 45 seconds.
- **It is stateless.** Run as many replicas as you like behind a plain load balancer; no session
  affinity is needed. Each replica keeps only its 30-second token cache and the Ory Hydra keys.

## Start up

At start the server:

1. reads its configuration from the environment ([configuration.md](configuration.md)) and stops if
   no bearer mode is on, `MCP_ACCEPT_API_TOKENS` isn't a boolean, or Ory Hydra mode lacks
   `MCP_RESOURCE_URL`;
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. builds the verifiers and the tool set (nothing is fetched yet: the JWKS is loaded on the first
   JWT, and the gateway is called on the first token);
4. serves HTTP on `HTTP_PORT`.

The start-up line `mcp starting` lists the port, which bearer modes are on, the Ory Hydra issuer and
audience, the resource URL and the gateway URL. A stop is a fatal log line and a non-zero exit.
`SIGINT` or `SIGTERM` shuts the server down, giving open requests 5 seconds.

## Health

- `GET /livez` is liveness. It answers `200` whenever the process does, and checks no dependency,
  so a gateway or Hydra outage never restarts the pod.
- `GET /readyz` is readiness. It answers `503` while a required dependency is down, and `200`
  otherwise, recovering on its own. Checks are cached for 5 seconds; each has a 1-second timeout.
- Both carry the build in `Sneakers-Version` and `Sneakers-Commit` headers (go-buildinfo); the
  gateway's diagnostics read them from `/livez`. There is no plain `/health` route.

The dependencies:

| Name | Required | Why |
|---|---|---|
| `gateway` | yes | Every tool call is a machine GraphQL call to the gateway, so the server can't do anything without it. Checked with `GET /readyz` on the origin of `GATEWAY_MACHINE_GRAPHQL_URL`, without a token. |
| `hydra-jwks` | only when Hydra is the only bearer mode | It verifies Hydra bearers. With `MCP_ACCEPT_API_TOKENS` on, API-token callers still work while it's down, so it only degrades readiness. Listed only when `HYDRA_ISSUER` is set; checked with `GET` on `HYDRA_JWKS_URL`. |

Each state change logs one line: `dependency check failing` at warn (with the error class) or
`dependency recovered` at info. Neither carries an address or the error text.

The kubelet probes are set in sneakers-release's chart: liveness on `/livez`, readiness on
`/readyz`.

The version and commit are the binary's build, stamped by the image build from its `VERSION` and
`COMMIT` build arguments into go-buildinfo's `Version` and `Commit` (`dev`, and Go's VCS revision
or `unknown`, when unstamped).
`SERVICE_VERSION` changes only the version in MCP `serverInfo`, never this answer.

```bash
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

## Logs

JSON on stderr by default. The lines to know:

| Message | Fields | Meaning |
|---|---|---|
| `http` | `method`, `path`, `status`, `dur` | One per request, except `/livez` and `/readyz`. Never headers or bodies. |
| `mcp tool call` | `tool`, `sub`, `outcome`, `dur` | One per tool call. Never arguments or results. |
| `mcp bearer rejected` | `reason`, `path` | A bearer was refused (warn). The reason names the check that failed, never the token. |

At start the OpenTelemetry SDK, which also reads `OTEL_EXPORTER_OTLP_ENDPOINT`, prints two
plain-text `parse url` lines when it holds the `host:port` form; export still works.

`outcome` is `ok`, `unauthenticated`, `invalid_input`, `gateway_denied_or_failed` (a GraphQL error,
such as a RACI denial), `gateway_http_<status>` or `error` (the gateway couldn't be reached or gave
an unusable answer). `sub` is the Ory Hydra subject, or the token label described in
[configuration.md](configuration.md).

## Common problems

- **Every token caller gets `401`.** The log shows `mcp bearer rejected` with a gateway reason:
  `gateway unreachable` or `gateway unavailable (HTTP <n>)` means the gateway is down or the URL is
  wrong; `gateway rejected the API token` means the gateway doesn't know the token (revoked,
  expired, or minted on another install).
- **JWT callers get `401`.** `JWT bearer but Hydra is not configured` means `HYDRA_ISSUER` is
  unset. Otherwise the reason names the failed claim: check that `HYDRA_ISSUER` matches the
  token's `iss` exactly, including the trailing slash, and that `HYDRA_AUDIENCE` is in its `aud`.
  `jwks fetch` reasons mean `HYDRA_JWKS_URL` isn't reachable. Keys are cached for 10 minutes and
  refetched at most every 30 seconds for an unknown key id.
- **An OAuth client can't find where to sign in.** Set `MCP_RESOURCE_URL` and
  `MCP_AUTHORIZATION_SERVER`, then check
  `GET /.well-known/oauth-protected-resource/mcp`.
- **`sneakers_test_secret` always says pending.** No connector picked the check up within 45
  seconds. The check stays queued; call again later, and check that a connector serves the target.
