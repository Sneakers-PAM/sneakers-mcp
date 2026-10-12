#!/usr/bin/env bash
# Vendors the SELECT fields of the vault's built-in type catalogue
# (gen/catalogue/types.json) at the commit pinned in vault-catalogue.env. The
# write tools list each SELECT field's options from them. Only the SELECT
# fields are kept: the rest of the catalogue isn't used here.
#
# SNEAKERS_VAULT_CATALOGUE points at a local types.json instead, for trying an
# unmerged vault change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/vault-catalogue.env"

dest="$root/internal/tools/vault-select-fields.json"
selects='{types: [.types[] | {id, fields: [.fields[] | select(.kind == "SELECT")]} | select(.fields | length > 0)]}'
if [[ -n "${SNEAKERS_VAULT_CATALOGUE:-}" ]]; then
  echo "catalogue: SELECT fields of $SNEAKERS_VAULT_CATALOGUE"
  jq "$selects" "$SNEAKERS_VAULT_CATALOGUE" > "$dest"
  exit 0
fi
echo "catalogue: SELECT fields of sneakers-vault gen/catalogue/types.json at $SNEAKERS_VAULT_REF"
curl -sSfL "https://raw.githubusercontent.com/Sneakers-PAM/sneakers-vault/$SNEAKERS_VAULT_REF/gen/catalogue/types.json" |
  jq "$selects" > "$dest"
