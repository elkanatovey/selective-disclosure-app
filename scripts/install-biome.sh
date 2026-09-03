#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIOME_VERSION=2.5.12
TOOLS_DIR=${TOOLS_DIR:-$ROOT/.tools/bin}

case $(uname -m) in
  x86_64)
    asset=biome-linux-x64
    sha256=e2475688799c9e78dd25ba5cf676676ffe74caf182a35082b1d22039151fdf63
    ;;
  aarch64 | arm64)
    asset=biome-linux-arm64
    sha256=4c1c9908e5cfd5d327e4ac3205baa13b1d3dfd24f184ed289a0c0ef1b2e0274f
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "$TOOLS_DIR"
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
curl -fsSL \
  "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%40${BIOME_VERSION}/${asset}" \
  -o "$temporary"
echo "$sha256  $temporary" | sha256sum -c -
install -m 0755 "$temporary" "$TOOLS_DIR/biome"
"$TOOLS_DIR/biome" --version
