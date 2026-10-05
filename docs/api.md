# API

## Routes

| Route | Auth | What it does |
|---|---|---|
| `POST /mcp` | bearer | MCP over Streamable HTTP, stateless mode. Requests are capped at 1 MiB and must pass Go's cross-origin protection. |
| `GET /health` | none | `{"status":"ok","version":"<tag>","commit":"<sha>"}`, for the gateway's diagnostics. Not logged. |
| `GET /livez` | none | Liveness: `{"status":"ok"}` whenever the process answers. It checks no dependency. Not logged. |
| `GET /readyz` | none | Readiness: `200` while every required dependency is up (`ok` or `degraded`), `503` while one is down. The body lists each dependency's `name`, `state` (`ok`, `degraded`, `down`), `required`, `error` (one of `timeout`, `refused`, `unavailable`, `unauthenticated`, `error`; never the error text), `checkedAt` and `version` when known. Checks are cached for 5 seconds, each with a 1-second timeout. Not logged. |
| `GET /.well-known/oauth-protected-resource` and `.../oauth-protected-resource/mcp` | none | RFC 9728 protected-resource metadata. Served only when `MCP_RESOURCE_URL` is set. |

A missing or rejected bearer on `/mcp` gets `401` with a `WWW-Authenticate` header that points at
the metadata (when it is served), and nothing about why. [configuration.md](configuration.md)
describes the bearer modes.

## How a tool call works

Every tool call carries the caller's own bearer to the gateway's `/machine/graphql`, unchanged. The
MCP server checks only that the call is authenticated and that its input is within bounds (ids up
to 128 bytes, names up to 256, field keys up to 128, values up to 16 KiB, at most 32 fields); the
gateway resolves the token and the vault decides access and writes the audit trail. GraphQL errors
such as a RACI denial come back to the agent as tool errors with the gateway's message; transport
failures come back as a generic gateway error. Every result is returned both as structured content
and as the same JSON in the text content, for clients that read only text.

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `sneakers_find_secrets` | read | Secrets the caller may read, by name substring, folder or type. Metadata only, never values. |
| `sneakers_list_folders` | read | Folders the caller may read, with path and `canAuthor`. |
| `sneakers_list_secret_types` | read | The type catalog: ids and fields (kind, required, sensitive). |
| `sneakers_get_secret` | read | One field of one secret. A non-sensitive field is audited as a read, a sensitive one as a reveal. When the secret needs approval for each personal-token reveal, it returns `approvalRequired`, an `approvalUrl`, a `useId`, a `runId` and the run's `pending` list instead of a value. Optional `runId` and `task` group one task's requests on one approval page. |
| `sneakers_redeem_reveal` | read | Collects a personal token's approved reveal by `useId`, once, within 60 seconds of approval; returns the `approvalUrl` again while it's pending. |
| `sneakers_create_secret` | write | A new secret with caller-supplied values. Optional `disableRotation` and `disableHeartbeat`. |
| `sneakers_generate_secret` | write | A new secret with a policy-compliant generated password, returned only when `returnValue` is true. |
| `sneakers_update_secret` | write | Sets non-sensitive fields of an existing secret. See [sneakers-update-secret.md](sneakers-update-secret.md). |
| `sneakers_move_secret` | destructive | Moves a secret to another folder, which changes who can reach it. Author on both folders; never into a personal folder. |
| `sneakers_change_secret_type` | destructive | Re-keys a secret into another type. Never drops a value: one with no field in the new type is appended to its notes field as `[moved from <key>]: <JSON string>`, or the call fails. The result's `automation` says what happened to rotation, heartbeat and the target. |
| `sneakers_rename_secret` | write | The name only; values are never read or returned. |
| `sneakers_create_folder` | write | A folder under a parent the caller can author; never at the top level or inside a personal tree. |
| `sneakers_rename_folder` | write | A folder the caller can author, including in their own personal tree. |
| `sneakers_set_secret_automation` | write | Turns rotation and heartbeat off or on; both flags are set on every call. |
| `sneakers_list_connections` | read | The connection profiles (protocol, port, TLS) a target can bind to. |
| `sneakers_list_targets` | read | Shared targets and the caller's own, each with `hostKeyFingerprints`: the SHA256 fingerprints of its pinned SSH host keys. |
| `sneakers_save_target` | write | Creates a personal target, or updates one of the caller's own. The hostname is validated first. `hostKeys` pins its SSH host keys (site admins only). |
| `sneakers_set_secret_target` | write | Attaches or detaches a secret's target. |
| `sneakers_test_secret` | check | Checks the stored credential against its target through a connector: ok, failed (with the reason) or unreachable, never a value. |

Names may not contain `/`, because folder paths are joined with it.

### Reveals that need approval

For a secret whose owner approves each personal-token reveal, `sneakers_get_secret` prepares the reveal and
returns its `approvalUrl` and `useId`. The result tells the agent to open the page in the user's
browser at once with its own opener (`$BROWSER`, `xdg-open` or `open`): the server can't open
anything on the user's machine, and a link left in a transcript tends to expire unseen. After the
owner approves with their second factor, `sneakers_redeem_reveal` collects the value once.

### One approval page per run

The requests one task raises share a run, so the owner approves them on one page with one second
factor instead of one visit per secret. The server is stateless, so the agent carries the run:

- The first `sneakers_get_secret` that needs approval, called without `runId`, starts a run: the
  bridge mints an id (`run_` and 128 random bits in base32) and returns it as `runId`.
- The agent passes that `runId` on every later request of the same task, asks for every secret the
  task needs first, and then opens `approvalUrl` once. A new task starts without a `runId`.
- `runId` must be 1 to 64 letters, digits, `_` or `-`; anything else is an input error.
- `task` is one line saying what the agent is doing. It is sent to vault as the use's purpose and
  shown to the owner as plain text. The bridge drops invalid UTF-8 and control characters,
  collapses whitespace to single spaces and cuts it to 200 characters before sending it.
- `pending` lists every use still waiting in the run (`useId`, `secretName`, `fieldKey`, `reveal`,
  `expiresAtUnix`), read from the gateway's `secretUseRun`. If the gateway can't list the run, it
  holds just the use this call raised.
- `approvalUrl` is the gateway's link for the run: `/approvals/run/<runId>` once the gateway's
  `APPROVAL_RUN_LINKS` is on, the Approvals list before that.
- Each approved use is still collected on its own with `sneakers_redeem_reveal`, within 60 seconds
  of approval.

```json
{
  "approvalRequired": true,
  "runId": "run_...",
  "approvalUrl": "https://sneakers.example.org/approvals/run/run_...",
  "useId": "use_...",
  "pending": [{ "useId": "use_...", "secretName": "db-admin", "fieldKey": "password", "reveal": true, "expiresAtUnix": 1790000000 }],
  "message": "..."
}
```

Runs cover personal tokens only, the same as token approval: service accounts are never held for
approval, so they have nothing to batch.

Token approval covers personal tokens only. A service-account token's reveal is never held for
approval: it is governed by the account's access rules and the vault's "Allow API access to
sensitive secrets" setting (off by default, which keeps super-sensitive fields from service
accounts and personal tokens alike).

### Checking a credential

`sneakers_test_secret` needs a heartbeat-capable type with a target. It asks for a check, then polls
the status every 2 seconds for up to 45 seconds and returns the first result newer than the
request; after that it reports the check as pending. The vault allows one check a minute per
secret: when it refuses with `ResourceExhausted`, the tool returns the latest result instead. When
the vault reports that no connector is available in this environment, the tool returns
`available: false` with a message, without waiting. Other errors are tool errors.

### SSH host keys

The SSH broker connects only to a host that presents one of its target's pinned SSH host keys, and
refuses a target with none. `sneakers_save_target` takes `hostKeys`, the whole pin list: one
OpenSSH public key per entry, the line from the host's `/etc/ssh/ssh_host_ed25519_key.pub` (or
another `ssh_host_*_key.pub`). Leave it out to keep the target's current pins, send `[]` to clear
them. The vault checks every key and lets only a human site admin change the pins, so a token gets
`PermissionDenied` when it sends a different list. Before the call leaves the MCP server, more than
16 keys, an empty or over-long entry, or a private key is refused, and the error names the entry
by position only. Results show pins as `hostKeyFingerprints` (as `ssh-keygen -l` prints them),
never the keys; an empty list means the target isn't pinned.

### The SSH broker

No tool reaches the SSH broker service, and the MCP server has no client for it. Brokered sessions
are started by a person in the web app only.

## Client setup

### A static token

Mint a service-account API token with the gateway's `mintApiToken` (an admin action; the token is
shown once), or use your own personal token from `/login`. Then give the MCP client the URL and a
static `Authorization` header. Most clients take a JSON config of this shape:

```json
{
  "mcpServers": {
    "sneakers": {
      "type": "http",
      "url": "https://sneakers-mcp.example.org/mcp",
      "headers": { "Authorization": "Bearer ${SNEAKERS_API_TOKEN}" }
    }
  }
}
```

Keep the token in a secret store or an environment variable, never in a committed file.

### Signing in

With `MCP_RESOURCE_URL` and `MCP_AUTHORIZATION_SERVER` set, an OAuth-capable MCP client reads the
protected-resource metadata, sends the user to the Sneakers sign-in, and receives a personal token.

## Scopes

The MCP server never reads scopes; the gateway takes the RACI groups identity resolves from the
token. OAuth2 scope tokens are space-separated, so a group is written as one of:

- its **group id**, exactly (preferred: it survives renames and never collides), or
- its **slug**: the name trimmed, each run of whitespace turned into `-`, ASCII-lowercased
  (`Help Desk` becomes `help-desk`). Matching is case-insensitive, and a name without spaces still
  works as written.

A slug shared by two groups, a slug equal to another group's id, or a group whose exact name is
duplicated grants nothing; use the id. A name with any non-ASCII character has no slug. Unknown
tokens are ignored.

A client only ever holds groups a site admin allowed: `linkOidcClient(serviceAccountId,
oidcSubject, allowedGroups)` takes ids or exact names, refuses anything that doesn't resolve to
exactly one group, and stores ids. An empty `allowedGroups` grants no groups. For example, an Ory
Hydra client with `scope: "group-helpdesk platform-team"` and `allowedGroups: ["Help Desk", "Platform
Team"]`. API tokens from `mintApiToken` use the same grammar; their mint-time scope is the bound.
