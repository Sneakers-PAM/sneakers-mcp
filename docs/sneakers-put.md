# sneakers-put

`sneakers-put` creates a secret, or updates fields of an existing one, with
values read from files or stdin on your machine. Use it whenever a value
already exists on disk, or would otherwise pass through an agent session or
your shell history. The MCP tools `sneakers_create_secret` and
`sneakers_generate_secret` point agents here for that reason.

```sh
export SNEAKERS_URL=https://sneakers.example.org
sneakers-put login   # once: sign in in your browser; the token goes to the Keychain

# Create. The folder and type ids come from sneakers_list_folders and
# sneakers_list_secret_types.
sneakers-put -folder <folder id> -type <type id> -name "router-01 admin" \
  -field username=admin -field password=@./router-01.pw

# Create a credential that must never rotate, for example a recovery password.
sneakers-put -folder <folder id> -type <type id> -name "recovery-admin" \
  -disable-rotation -field password=-  < ./recovery.txt

# Update fields of an existing secret.
sneakers-put -id <secret id> -field password=@./new.pw
```

`sneakers-put -h` prints the full usage (modes, flags, field forms,
environment and examples) and exits 0. A usage error prints the error and
the same usage to stderr and exits 2.

## Signing in

`sneakers-put login` (or `sneakers-run login`, which is the same) signs you in to `SNEAKERS_URL`
in your browser and keeps the personal token it gets in the macOS Keychain, so you never copy a
token:

```sh
export SNEAKERS_URL=https://sneakers.example.org
sneakers-put login
```

It uses the gateway's OAuth sign-in for native clients, the one an MCP client uses: it registers a
client with a loopback redirect URI, opens the gateway's sign-in and consent page (your second
factor, and the consent naming `sneakers-put on <this host>`), takes the code on `127.0.0.1` with a
PKCE `S256` check, and exchanges it for a personal token (`snk_u_...`). `-no-open` prints the link
instead of opening a browser (`$BROWSER`, else `xdg-open` or `open`). The token goes into the login
Keychain as a password item with the service `Sneakers-PAM` and the gateway host as the account,
written through `security`'s standard input, never its command line. It's never printed.

- Every later run reads the token from the Keychain for the gateway `SNEAKERS_URL` names.
  `SNEAKERS_TOKEN`, when set, is used instead.
- Run `login` again to replace the token. `sneakers-put logout` removes it from the Keychain;
  revoke it on the Tokens page to end it on the gateway too.
- The Keychain is macOS only. Elsewhere `login` refuses, and `SNEAKERS_TOKEN` must hold a personal
  token.
- The gateway records the token like an MCP client's (`client_kind: mcp`), so while MCP is turned
  off on the appliance (the `mcp.enabled` setting), `login` and the token are refused.

## Fields

Each `-field` is one of:

| Form | Value comes from |
|---|---|
| `key=@path` | the file at `path` |
| `key=-` | stdin; only one field per call may use it |
| `key=value` | the command line; only for non-secret fields |

A literal `key=value` is accepted only when the secret's type declares `key`
as a `TEXT`, `BOOLEAN` or `SELECT` field. For `PASSWORD`, `SENSITIVE`,
`MULTILINE` or `FILE` fields, and for keys the type does not declare, the
command stops and tells you to use `key=@file` or `key=-`. It learns the
kinds from the type catalog (`secretTypes`); on update it looks up the
secret's type first. Nothing is written when a literal is refused.

One trailing newline (`\n` or `\r\n`) is trimmed from file and stdin values,
so `echo` and editors don't add one to the stored value. Nothing else is
touched: a base64 value keeps its `=` or `==` padding, and newlines inside
the value are kept. An empty value, or one over 16 KiB, is refused.

## Output

On success it prints only:

```
id: <secret id>
name: <secret name>
changed: <field keys>      # update only
folder: <folder id>        # create, when the gateway reports a placement
placement: <rule>: <reason>
```

It never prints a value. If a gateway error happens to quote a value you
supplied from a file or stdin, that value is replaced with `[redacted]`.

## Rules

- The token is the one `sneakers-put login` stored, or `SNEAKERS_TOKEN`, and
  must be a personal token (`snk_u_...`). Service-account tokens are refused.
- `SNEAKERS_URL` must be `https://`. Plain `http://` is accepted only for
  localhost with `-insecure-localhost`, for testing against a local gateway.
- Access is checked by the gateway and vault as for the UI: author rights on
  the folder for a create, on the secret for an update. Both are audited as
  you.
- On update, each key must be a field of the secret's type, and the result is
  a new version, so earlier values stay in history. On types the vault
  manages (rotation, heartbeat, checkout, certificate) only `notes` and
  `description` can be changed this way; the vault rotates the rest.
- `-disable-rotation` and `-keep-folder` are for creates only. To change
  rotation or heartbeat on an existing secret, use the MCP tool
  `sneakers_set_secret_automation`.
- A new secret whose name, or a username, login, email or account field,
  names you goes to your Personal folder, not `-folder`; `-keep-folder` keeps
  `-folder` (say, for a shared admin account that carries your name). The
  `placement` line names the rule and the reason; see
  [api.md](api.md#placement).

It uses the gateway's `createSecretForPrincipal` (with `disableRotation` and
`keepFolder`) and `updateSecretFieldsForPrincipal`.
