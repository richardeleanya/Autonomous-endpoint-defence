#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || ! -d "$1" || ! -d "$2" ]]; then
  echo "Usage: $0 NATIVE_BUILD_DIRECTORY EXISTING_EMPTY_OUTPUT_DIRECTORY" >&2
  exit 2
fi
input=$(realpath -e -- "$1")
out=$(realpath -e -- "$2")
if [[ -n "$(find "$out" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo 'Output directory must be empty.' >&2
  exit 2
fi
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
umask 077
lab=$(mktemp -d)
trap 'rm -rf -- "$lab"' EXIT
openssl req -x509 -newkey rsa:3072 -noenc -days 7 -subj '/CN=ADA isolated lab code signing' \
  -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=codeSigning' \
  -keyout "$lab/signer.key" -out "$lab/signer.pem" > "$lab/keygen.log" 2>&1
install -m 0644 "$lab/signer.pem" "$out/LAB-SIGNER.pem"
install -m 0755 "$input/ada-agent-linux-amd64" "$out/ada-agent-linux-amd64"

install -Dm0755 "$input/ada-agent-linux-amd64" "$lab/package/usr/bin/ada-agent"
mkdir -p "$lab/package/DEBIAN"
chmod 0755 "$lab/package" "$lab/package/usr" "$lab/package/usr/bin" "$lab/package/DEBIAN"
cat > "$lab/package/DEBIAN/control" <<'CONTROL'
Package: ada-agent
Version: 0.1.0
Architecture: amd64
Maintainer: Autonomous Endpoint Defence Lab
Description: TLS observe-only endpoint heartbeat agent
CONTROL
SOURCE_DATE_EPOCH=$(git -C "$repo" show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH
dpkg-deb --build --root-owner-group "$lab/package" "$out/ada-agent_0.1.0_amd64.deb"

signer=$(docker build --quiet - <<'DOCKER'
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends osslsigncode=2.5-4 && rm -rf /var/lib/apt/lists/*
DOCKER
)
{
  printf 'LAB signing only\n'
  printf 'Base Git commit '
  git -C "$repo" rev-parse HEAD
  printf 'Native source and build-script digests\n'
  (cd "$repo" && sha256sum product/agent/go.mod product/agent/main.go scripts/build-native-agents.sh)
  printf 'Toolchain '
  cat "$input/toolchain.txt"
  printf 'Authenticode signing-tool image %s\n' "$signer"
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$lab/signer.key,target=/signer.key,readonly" \
    --mount "type=bind,source=$out,target=/out" \
    --mount "type=bind,source=$input/ada-agent-windows-amd64.exe,target=/agent.exe,readonly" \
    "$signer" sh -ec '
      osslsigncode sign -certs /out/LAB-SIGNER.pem -key /signer.key -h sha256 \
        -n "ADA observe-only agent (lab)" -in /agent.exe -out /out/ada-agent-windows-amd64.exe
      osslsigncode verify -CAfile /out/LAB-SIGNER.pem -in /out/ada-agent-windows-amd64.exe
    '
  for artifact in ada-agent-linux-amd64 ada-agent_0.1.0_amd64.deb; do
    openssl cms -sign -binary -md sha256 -nosmimecap -in "$out/$artifact" \
      -signer "$lab/signer.pem" -inkey "$lab/signer.key" -outform DER -out "$out/$artifact.p7s"
    openssl cms -verify -binary -inform DER -in "$out/$artifact.p7s" \
      -content "$out/$artifact" -purpose any -CAfile "$out/LAB-SIGNER.pem" \
      -no-CApath -no-CAstore -out /dev/null
  done
  dpkg-deb --extract "$out/ada-agent_0.1.0_amd64.deb" "$lab/extracted"
  cmp "$out/ada-agent-linux-amd64" "$lab/extracted/usr/bin/ada-agent"
} > "$out/signing.log" 2>&1
(
  cd "$out"
  sha256sum -- LAB-SIGNER.pem ada-agent-* ada-agent_*.deb* signing.log > SHA256SUMS
  sha256sum --quiet -c SHA256SUMS
)
printf 'Verified lab signatures and digests in %s\n' "$out"
