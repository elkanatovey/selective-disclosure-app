#!/bin/bash
# Build the dev image (toolchain only). Run from the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE_TAG=${IMAGE_TAG:-sda-dev}

echo "Building dev image '$IMAGE_TAG'..."
docker build -t "$IMAGE_TAG" -f Dockerfile .
echo "Done. Start a dev container with: ./docker/dev.sh"
