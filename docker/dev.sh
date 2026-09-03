#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Start an interactive development container with the repository bind-mounted.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE_TAG=${IMAGE_TAG:-scitt-selective-disclosure-dev}
CONTAINER_NAME=${CONTAINER_NAME:-scitt-selective-disclosure-dev}

docker run --rm -it \
  --name "$CONTAINER_NAME" \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
  --publish 127.0.0.1:8000:8000 \
  --publish 127.0.0.1:8090:8090 \
  --publish 127.0.0.1:8091:8091 \
  --publish 127.0.0.1:8092:8092 \
  -v "$(pwd)":/workspace \
  -w /workspace \
  "$IMAGE_TAG" \
  /bin/bash -lc './.devcontainer/post-create.sh; exec /bin/bash'
