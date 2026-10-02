#!/usr/bin/env bash
# Cross-build the local commands into dist/<command>/, each with its own SHA256SUMS.
set -euo pipefail
commands=(sneakers-run sneakers-put)
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)
rm -rf dist
for cmd in "${commands[@]}"; do
  mkdir -p "dist/$cmd"
  for target in "${targets[@]}"; do
    os=${target%/*} arch=${target#*/}
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" \
      -o "dist/$cmd/$cmd-$os-$arch" "./cmd/$cmd"
  done
  (cd "dist/$cmd" && sha256sum "$cmd"-* > SHA256SUMS)
  cat "dist/$cmd/SHA256SUMS"
done
