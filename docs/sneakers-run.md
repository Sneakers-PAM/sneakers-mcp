# sneakers-run

`sneakers-run` runs one command with a secret field supplied to it, without the value passing
through the model or the shell history.

```sh
export SNEAKERS_URL=https://sneakers.example.org SNEAKERS_TOKEN=snk_u_...
sneakers-run -secret <id> -- ssh admin@router-01                 # value on stdin
sneakers-run -secret <id> -inject file -- tool --key {secret_file}
```

`sneakers-run -h` prints the full usage and exits 0. A usage error prints the error and the usage
to stderr and exits 2. Otherwise it exits with the command's own exit code, or 1 when the use
couldn't be prepared, approved or redeemed.

## How the value reaches the command

- It needs a personal token from `/login`. Service-account tokens are refused.
- The use is bound to this exact argv. The owner approves it on the Approvals page with a fresh
  second factor, unless a grant they created in the UI already covers it.
- The value is released once. `sneakers-run` refuses to run anything but the bound argv.
- The command's stdout and stderr have the value masked, including its base64, hex and URL
  encodings.
- On stdin the value is sent as stored, followed by one newline. Under `-inject file` it is written
  exactly as stored, with no newline added, to a 0600 temp file named by `{secret_file}` in the
  arguments and by `$SNEAKERS_SECRET_FILE`. The file is removed when the command exits.
- `SNEAKERS_TOKEN` is not passed to the command.
- A bare program name (`ssh`) is looked up only in `/usr/local/bin:/usr/bin:/bin`, never your
  `$PATH`, so a same-named file earlier on your PATH can't receive the value. Anything else must be
  an absolute path to an executable (`/opt/tools/bin/tool`); relative paths are refused. Grants
  match the program exactly as typed, bare name or absolute path.
- `SNEAKERS_URL` must be `https://`. Plain `http://` is accepted only for localhost with
  `-insecure-localhost`, for testing against a local gateway.

## Several commands on one approval page

Every use belongs to a run, and the owner approves all the pending uses of one run on one page with
one second factor. Without `-run-id`, each `sneakers-run` starts its own run, so a single command is
a batch of one. To put several commands on the same page, give them the same run id with `-run-id`
or `$SNEAKERS_RUN_ID` (the flag wins), and start them before approving:

```sh
export SNEAKERS_RUN_ID=run_deploy1
sneakers-run -purpose "deploy the app" -secret <db id> -- tool migrate &
sneakers-run -purpose "deploy the app" -secret <api id> -- tool publish
```

A run id is 1 to 64 letters, digits, `_` or `-`; anything else is a usage error. `-purpose` is one
line shown to the owner as plain text; control characters and invalid UTF-8 are dropped, whitespace
is collapsed and it is cut to 200 characters. The run id is printed with the approval link.

## Approvals open in your browser

When the gateway leaves a use pending, `sneakers-run` prints the approval link to stderr and opens
it in your browser, so the approval doesn't expire unseen in a terminal. It doesn't open anything
when a grant you created already covers the use, because there's nothing to approve.

The browser is chosen in this order:

1. `$BROWSER`, if it is set. It can be a command with arguments (`firefox --new-window`) or a
   `:`-separated list of them (`chromium --incognito:firefox`). The first entry whose program
   exists is used. A `%s` in an entry is replaced by the link; without one, the link is added as
   the last argument.
2. Otherwise `xdg-open` (Linux) or `open` (macOS), whichever is found first on your `PATH`.
3. If none of these are available, the link is only printed.

The browser is started in the background. `sneakers-run` doesn't wait for it, discards its output,
and never passes `SNEAKERS_TOKEN` to it. The page opens once per pending use.

Pass `-no-open` to only print the link, for example on a remote shell where the browser would open
on the wrong machine:

```sh
sneakers-run -no-open -secret <id> -- ssh admin@router-01
```
