#!/usr/bin/env bash
# Vendors the gateway's machine GraphQL schema at the commit pinned in
# gateway-schema.env, for the contract test in internal/contract.
#
# SNEAKERS_GATEWAY_SCHEMA points at a local machine.graphqls instead, for
# trying an unmerged gateway change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/gateway-schema.env"

dest="$root/internal/contract/testdata/machine.graphqls"
if [[ -n "${SNEAKERS_GATEWAY_SCHEMA:-}" ]]; then
  echo "schema: machine.graphqls from $SNEAKERS_GATEWAY_SCHEMA"
  cp "$SNEAKERS_GATEWAY_SCHEMA" "$dest"
  exit 0
fi
echo "schema: sneakers-gateway machine.graphqls at $SNEAKERS_GATEWAY_REF"
curl -sSfL "https://raw.githubusercontent.com/Sneakers-PAM/sneakers-gateway/$SNEAKERS_GATEWAY_REF/graphql/machine.graphqls" -o "$dest"
