#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Start an interactive dev container with the repo bind-mounted at /workspace.
# You edit on the host; you build/run inside this container.
#
# NET_ADMIN / NET_RAW / SYS_PTRACE are granted because CCF's sandbox.sh sets up
# a local network and may attach debuggers, mirroring CCF CI's container caps.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE_TAG=${IMAGE_TAG:-sda-dev}
CONTAINER_NAME=${CONTAINER_NAME:-sda-dev}

docker run --rm -it \
  --name "$CONTAINER_NAME" \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
  -v "$(pwd)":/workspace \
  -w /workspace \
  "$IMAGE_TAG" \
  /bin/bash
