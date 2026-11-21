#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -d "$1" ]]; then
  echo "Usage: $0 EXISTING_EMPTY_OUTPUT_DIRECTORY" >&2
  exit 2
fi
out=$(realpath -e -- "$1")
if [[ -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo 'Output directory must be empty.' >&2
  exit 2
fi
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
image=golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$repo/product/agent,target=/source,readonly" \
  --mount "type=bind,source=$out,target=/out" \
  -e GOCACHE=/tmp/go-cache -e GOTOOLCHAIN=local -e CGO_ENABLED=0 -w /source \
  "$image" sh -ec '
    gofmt -l main.go > /tmp/unformatted
    test ! -s /tmp/unformatted
    go vet ./...
    GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o /out/ada-agent-linux-amd64 .
    GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -o /out/ada-agent-windows-amd64.exe .
    go version > /out/toolchain.txt
  '
