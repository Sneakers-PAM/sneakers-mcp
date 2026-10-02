# sneakers_update_secret

`sneakers_update_secret` sets fields of an existing secret that hold no secret
value: a URL or endpoint, notes, a description and similar. It is how an agent
records a device address on a secret that already exists.

```json
{
  "id": "<secret id>",
  "fields": [
    { "key": "url", "value": "https://fw-01.example.org/" },
    { "key": "notes", "value": "Management interface on the OOB network." }
  ]
}
```

It returns the secret summary and `changedFieldKeys`, the keys whose value
changed. It never returns a value.

## Which keys it accepts

Before it calls the gateway, the tool looks up the secret's type (through
`findSecretsForPrincipal` and `secretTypes`) and checks every key:

- a key the type marks `sensitive` is refused;
- a key the type does not declare is refused, because it could hold a secret;
- a secret the token cannot see is refused.

A refusal writes nothing and points to the local
[sneakers-put](sneakers-put.md) command, which reads the value from a file so
it never passes through the transcript:

```sh
sneakers-put -id <secret id> -field password=@./new.pw
```

`sneakers_list_secret_types` shows each field's `sensitive` flag, so an agent
can check a key first.

## Limits

- `id` is required, at most 128 bytes.
- 1 to 20 fields per call, with no duplicate keys.
- Keys are at most 128 bytes, values at most 16 KiB, as for the other tools.

## Access and audit

The vault checks RACI Author on the secret and the token's limits. Each call
is audited as `secret.update.principal` with the changed field keys, never
values. The update is a new version, so earlier values stay in history. On
types the vault manages (rotation, heartbeat, checkout, certificate) the vault
lets only `notes` and `description` change this way.

## Gateway API

It uses the gateway's `updateSecretFieldsForPrincipal` mutation and the
`sensitive` flag on the machine `SecretTypeField`.
