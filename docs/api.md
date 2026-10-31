# API

## Routes

| Route | Auth | What it does |
|---|---|---|
| `POST /mcp` | bearer | MCP over Streamable HTTP, stateless mode. Requests are capped at 1 MiB and must pass Go's cross-origin protection. |
| `GET /livez` | none | Liveness: `{"status":"ok"}` whenever the process answers. It checks no dependency. Its `Sneakers-Version` and `Sneakers-Commit` headers are the build, which the gateway's diagnostics read. Not logged. |
| `GET /readyz` | none | Readiness: `200` while every required dependency is up (`ok` or `degraded`), `503` while one is down. The body is go-buildinfo's report: `status`, `ready`, `build` (`version`, `commit`, `goVersion`, `modified`) and each dependency's `name`, `state` (`ok`, `degraded`, `down`), `required`, `error` (a class such as `timeout`, `refused`, `unavailable`, `unauthenticated` or `error`; never the error text) and `checkedAt`. The headers carry the build and `Sneakers-Depstate-<name>`. The checks run in the background every 5 seconds, each with a 1-second timeout, and `/readyz` only reads their last result (`pending` before the first pass). Not logged. |
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

## Gateway contract

Every GraphQL operation the MCP server and the commands send is checked against the gateway's
machine schema in `internal/contract` (`go test ./internal/contract/`). The schema is vendored in
`internal/contract/testdata/machine.graphqls` at the gateway commit pinned in `gateway-schema.env`.
A field, argument or type the gateway doesn't have fails the test, where it would otherwise fail on
a running box as HTTP 422 `GRAPHQL_VALIDATION_FAILED`. Every query passed to the gateway client
must be a string constant, so the test sees all of them.

When the gateway's machine schema changes, set `SNEAKERS_GATEWAY_REF` to the gateway commit, run
`scripts/gateway-schema-fetch.sh` and commit the schema in the same change. Point
`SNEAKERS_GATEWAY_SCHEMA` at a local `machine.graphqls` to try an unmerged gateway change. A tool
that needs a new gateway field lands only after the gateway change is on its `main` and pinned
here.

## SELECT options

A SELECT field takes one of its type's options; the vault refuses any other value on every create
and update, with a message that names the field and lists the options, which the tool error
carries to the agent. A value that differs from one option only in letter case is stored as that
option. The descriptions of `sneakers_create_secret`, `sneakers_generate_secret` and
`sneakers_update_secret` list each built-in SELECT field with its options, read from the vault's
catalogue (`gen/catalogue/types.json`), whose SELECT fields are vendored in
`internal/tools/vault-select-fields.json` at the vault commit pinned in `vault-catalogue.env`. When the vault's catalogue changes, set `SNEAKERS_VAULT_REF` to the vault
commit, run `scripts/vault-catalogue-fetch.sh` (it needs `jq`) and commit the file in the same change. Point
`SNEAKERS_VAULT_CATALOGUE` at a local `gen/catalogue/types.json` to try an unmerged vault change.

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `sneakers_find_secrets` | read | Secrets the caller may read, by name substring, folder or type. Metadata only, never values. |
| `sneakers_list_folders` | read | Folders the caller may read, with path and `canAuthor`. |
| `sneakers_list_secret_types` | read | The type catalog: ids and fields (kind, required, sensitive). |
| `sneakers_get_secret` | read | One field of one secret. A non-sensitive field is audited as a read, a sensitive one as a reveal. When the secret needs approval for each personal-token reveal, it returns `approvalRequired`, an `approvalUrl`, a `useId`, a `runId` and the run's `pending` list instead of a value. Optional `runId` and `task` group one task's requests on one approval page. |
| `sneakers_redeem_reveal` | read | Collects a personal token's approved reveal by `useId`, once, within 60 seconds of approval; returns the `approvalUrl` again while it's pending. |
| `sneakers_create_secret` | write | A new secret with caller-supplied values. Optional `disableRotation` and `disableHeartbeat`. A secret that names you goes to your Personal folder unless `keepFolder` is true; see [Placement](#placement). |
| `sneakers_generate_secret` | write | A new secret with a policy-compliant generated password, returned only when `returnValue` is true. Same placement and `keepFolder` as create. |
| `sneakers_generate_ssh_key` | write | A new SSH Key secret with a key pair made on the Sneakers side. Returns only the public key line and its SHA-256 fingerprint, never the private key. See [Generating an SSH key](#generating-an-ssh-key). |
| `sneakers_update_secret` | write | Sets non-sensitive fields of an existing secret. See [sneakers-update-secret.md](sneakers-update-secret.md). |
| `sneakers_move_secret` | destructive | Moves a secret to another folder, which changes who can reach it. Author on both folders; never into a personal folder. |
| `sneakers_change_secret_type` | destructive | Re-keys a secret into another type. Never drops a value: one with no field in the new type is appended to its notes field as `[moved from <key>]: <JSON string>`, or the call fails. The result's `automation` says what happened to rotation, heartbeat and the target. |
| `sneakers_rename_secret` | write | The name only; values are never read or returned. |
| `sneakers_create_folder` | write | A folder under a parent the caller can author; never at the top level or inside a personal tree. |
| `sneakers_rename_folder` | write | A folder the caller can author, including in their own personal tree. |
| `sneakers_set_secret_automation` | write | Turns rotation and heartbeat off or on; both flags are set on every call. Turning heartbeat back on is refused, naming what's missing, unless the secret has a target with a connection and, for SSH Key, a pinned host key. |
| `sneakers_list_connections` | read | The connection profiles (protocol, port, TLS) a target can bind to. |
| `sneakers_list_targets` | read | Shared targets and the caller's own, each with `hostKeyFingerprints`: the SHA256 fingerprints of its pinned SSH host keys. |
| `sneakers_save_target` | write | Creates a personal target, or updates one of the caller's own. The hostname is validated first. `hostKeys` pins its SSH host keys, but no token can set or clear them, not even a site admin's; a person pins them in the admin app (Targets → Scan and pin). |
| `sneakers_set_secret_target` | write | Replaces a secret's whole target list with one target, or clears it. One secret can be attached to several targets; use attach/detach below to add or remove one without replacing the list. |
| `sneakers_attach_secret_target` | write | Attaches one target to a secret the caller can author, without touching its other targets. A no-op if already attached. |
| `sneakers_detach_secret_target` | write | Detaches one target from a secret, without touching its other targets. A no-op if it isn't attached. |
| `sneakers_rotate_secret` | destructive | Regenerates a secret's password field under its policy and stores it as a new version. Needs Author, never just read. The new value is always returned — store it, then set it on the target yourself. Refused while a scheduled rotation is already queued or running. |
| `sneakers_restore_secret_version` | destructive | Makes an earlier version current again, as a new version — never a history rewrite. Needs Author. Refused while a scheduled rotation is queued or running. |
| `sneakers_test_secret` | check | Checks the stored credential against its target through a connector: ok, failed (with the reason) or unreachable, never a value. |

Names may not contain `/`, because folder paths are joined with it.

### Reveals that need approval

Once signed in, a personal token gets no second factor and no approval for a secret its user can
read. The one exception is a secret with an approval level, decided by the vault:

| Requester | Normal | Approval-required | Always-approve |
|---|---|---|---|
| An owner of the secret | no approval | no approval | another owner or a designated approver decides |
| A non-owner with read access | no approval | any one owner decides | an owner or a designated approver decides |
| No read access | refused | refused | refused |

The user never approves their own request. When nobody else can decide (a single-user install, or
an always-approve secret whose only approver is the user), the user confirms the task once in the
browser with their second factor instead, and the result says so with `confirmRequired`.
Break-glass is for people only, not the MCP or any agent: the gateway refuses it to anything but
a person's own signed-in web session, so it isn't reachable through the MCP, and never will be.

For such a reveal, `sneakers_get_secret` prepares it and returns its `approvalUrl` and `useId`. The
result tells the agent to open the page in the user's browser at once with its own opener
(`$BROWSER`, `xdg-open` or `open`): the server can't open anything on the user's machine, and a link
left in a transcript tends to expire unseen. Once an owner or approver approves it, or the user
confirms it, `sneakers_redeem_reveal` collects the value once.

### One approval page per run

The requests one task raises share a run, so they're decided or confirmed on one page with one
second factor instead of one visit per secret, and once the user confirms a run, its later requests
need nothing more. The server is stateless, so the agent carries the run:

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

`sneakers_test_secret` needs a heartbeat-capable type with a target whose heartbeat is actually
running — for an SSH Key secret, the target also needs a pinned host key; `heartbeatEnabled` on
the secret says whether it is. It asks for a check, then polls
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
them. The vault checks every key and lets only a human site admin change the pins; no token can,
not even a site admin's, because pinning decides which server a credential may be sent to, which
stays with a person on purpose. A token that sends a different list gets `PermissionDenied` saying
so, not a missing-role message. Before the call leaves the MCP server, more than
16 keys, an empty or over-long entry, or a private key is refused, and the error names the entry
by position only. Results show pins as `hostKeyFingerprints` (as `ssh-keygen -l` prints them),
never the keys; an empty list means the target isn't pinned.

### Generating an SSH key

`sneakers_generate_ssh_key` makes an SSH key pair inside the MCP server and stores it as a new SSH
Key secret in one call, so the private key never passes through the agent or its transcript.

| Argument | |
|---|---|
| `folderId`, `name` | Required, as for `sneakers_create_secret`. |
| `keyFormat` | `Ed25519` (the default), `RSA 4096`, `RSA 2048` or `ECDSA P-256`, the SSH Key type's options. |
| `comment` | Ends the public key line, such as `deploy@build-01`. One line. |
| `username` | Stored in the type's `username` field. One line. |
| `typeId` | Default `type-ssh-key`. Another type must declare `privateKey` and `publicKey` fields, or the call is refused before a key is made. |
| `targetId`, `disableRotation`, `disableHeartbeat`, `keepFolder` | As for `sneakers_create_secret`. |

It stores the same fields the web's key pair generator fills: `privateKey` (an unencrypted
OpenSSH private key), `publicKey` (the `authorized_keys` line), `keyFormat` and `username`, so a key
made either way is the same kind of secret. The key comes from `crypto/rand` the same way the
vault's own generator makes it. The result has the secret's summary and placement, `publicKey`,
`fingerprint` (`SHA256:...`, as `ssh-keygen -l` prints it) and `keyFormat`, never the private key.
Install the public key line on the hosts the key signs in to. A person reads the private key on the
web, and `sneakers-run -field privateKey -inject file` hands it to a command.

The vault audits the call as a secret creation by the token's user or service account, and needs
author access to the folder. The MCP server's log line names the tool, the subject and the outcome
only; at `debug` it adds the key format and the public fingerprint. If the gateway's error ever
quoted the key, the agent gets a fixed message instead.

### The SSH broker

No tool reaches the SSH broker service, and the MCP server has no client for it. Brokered sessions
are started by a person in the web app only.

### One secret, many targets

A secret can be attached to more than one target (one SSH key opening sessions on every host it's
attached to). `secretId`/`targetId` throughout mean the same ids `sneakers_list_targets` and
`sneakers_get_secret`/`sneakers_find_secrets` already return; `targetId` on a result is the
first/primary attached target, `targetIds` lists all of them. `sneakers_set_secret_target` keeps
its existing meaning: replace the whole list with just one (or clear it). Host-key pins stay per
target, unaffected by any of this.

### Rotate and restore

`sneakers_rotate_secret` and `sneakers_restore_secret_version` need Author on the secret (the same
grant `sneakers_create_secret` needs), never just read — a token that can only reveal a secret
cannot rotate or restore it. `sneakers_rotate_secret`'s new value is always returned, since the
whole point of calling it is to push the value to the target next: store it, then set it on the
host yourself, and call `sneakers_restore_secret_version` with the prior version number if that
fails. Both are refused while a scheduled rotation of the secret is already queued or running.

## Client setup

### A static token

Mint a service-account API token with the gateway's `mintApiToken` (an admin action; the token is
shown once). A person's own token comes from an OAuth sign-in (below, or `sneakers-put login`,
which keeps it in the macOS Keychain or the Linux keyring, or a `0600` file on a headless Linux box); no page shows one to copy. Then give the MCP client the URL and a
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

## Placement

A new secret from `sneakers_create_secret`, `sneakers_generate_secret` or
`sneakers-put` whose name, or a username, login, email or account field, names
the token's owner (their username as a whole word, or their email, ignoring
case) goes to the owner's Personal folder instead of `folderId`, because a
token can't move it there later. `keepFolder` (`-keep-folder` for
sneakers-put) keeps `folderId`. The result's `placement` gives the folder
used, the folder asked for, the rule (`REQUESTED`, `PERSONAL_DEFAULT`,
`KEPT_BY_CALLER`, `ALREADY_PERSONAL` or `NO_PERSONAL_FOLDER`) and the reason,
which names the matching part, never a value. The gateway decides; this needs
the gateway's `keepFolder` argument and `SecretSummary.placement`.

## Change signals

So an agent knows when a value it holds may have gone stale, every secret
summary carries `valueVersion` (goes up whenever the stored value changes;
re-fetch and re-scan when it differs from the one you read), `valueChangedAt`,
`rotationEnabled`, `rotatesOnCheckin` (checking the secret in after a
check-out rotates the value), `heartbeatEnabled`, and the last rotation and
heartbeat results. None carry a value.

`heartbeatEnabled` false on a heartbeat-capable type can mean it's opted out, or that the target
isn't ready yet: no target, no connection, or (SSH Key only) no pinned host key — a new secret's
heartbeat starts off until that's true, rather than failing checks from the first poll. When it's
the latter, `heartbeatBlockedReason` names exactly what's missing ("no target", "no connection" or
"no pinned host key"); it's absent once heartbeat is running or opted out on purpose. Fix what's
missing, then turn it on with `sneakers_set_secret_automation`; asking before then is refused,
naming what's still missing.

- `sneakers_find_secrets` takes `changedSince` (RFC3339) to list only secrets
  whose value changed at or after that time; a bad time is refused before the
  gateway is called.
- `sneakers_get_secret` reads the secret's summary just before the value and
  returns it as `secret`, so the version it reports is never newer than the
  value. If the gateway can't return the summary, the value still comes back,
  without `secret`.

These need the gateway's `secretForPrincipal` and the `changedSince` argument.
