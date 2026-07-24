#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Build CCF from source (all options ON), installing into /workspace/.ccf-install.
# Parallelism is throttled to avoid OOM on a 16 GB machine: compiles run with
# $NPROC_COMPILE jobs but only $NPROC_LINK links run concurrently (links are the
# memory-heavy step). Run this INSIDE the dev container.
set -euo pipefail
cd "$(dirname "$0")/.."

NPROC_COMPILE=${NPROC_COMPILE:-6}
NPROC_LINK=${NPROC_LINK:-2}
BUILD_DIR=${BUILD_DIR:-third_party/CCF/build}
INSTALL_DIR=${INSTALL_DIR:-/workspace/.ccf-install}

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_JOB_POOLS="compile=${NPROC_COMPILE};link=${NPROC_LINK}" \
  -DCMAKE_JOB_POOL_COMPILE=compile \
  -DCMAKE_JOB_POOL_LINK=link \
  ..

ninja
ninja install

echo "CCF installed to $INSTALL_DIR"
