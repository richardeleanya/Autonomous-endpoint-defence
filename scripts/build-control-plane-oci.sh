#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ! -d "$1" || ! -d "$2" ]]; then
  echo "Usage: $0 VERIFIED_WHEEL_DIRECTORY EXISTING_EMPTY_OUTPUT_DIRECTORY" >&2
  exit 2
fi
wheels=$(realpath -e -- "$1")
out=$(realpath -e -- "$2")
if [[ -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo 'Output directory must be empty.' >&2
  exit 2
fi
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
epoch=$(git -C "$repo" show -s --format=%ct HEAD)
base=python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/layout"
if ! docker image inspect "$base" >/dev/null 2>&1; then
  docker pull --platform linux/amd64 "$base"
fi
docker image save --platform linux/amd64 --output "$work/base.tar" "$base"
tar --extract --file "$work/base.tar" --directory "$work/layout" -- blobs index.json oci-layout
base_manifest=$(python3 -c '
import json, re, sys
with open(sys.argv[1]) as source:
    index = json.load(source)
descriptor, = index["manifests"]
digest = descriptor["digest"]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("Invalid base image descriptor")
print(digest)
' "$work/layout/index.json")
docker buildx build --platform linux/amd64 --no-cache --network none \
  --build-arg "SOURCE_DATE_EPOCH=$epoch" --build-arg "PYTHON_BASE=ada-python-base" \
  --build-context "ada-python-base=oci-layout://$work/layout@$base_manifest" \
  --build-context "wheelhouse=$wheels" \
  --provenance=false --sbom=false \
  --output "type=oci,dest=$out/control-plane.oci.tar,name=ada-control-plane:release,compression=uncompressed,rewrite-timestamp=true" \
  "$repo/product/control_plane"
