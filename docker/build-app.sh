#!/bin/bash
# Build the selective-disclosure app against the locally built+installed CCF.
# Run this INSIDE the dev container, after docker/build-ccf.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL_DIR=${INSTALL_DIR:-/workspace/.ccf-install}
BUILD_DIR=${BUILD_DIR:-app/build}

# CCF is built with Clang and its headers are Clang-only (e.g. in-class template
# specializations that GCC rejects). The app MUST use the same toolchain, so
# pin Clang here rather than relying on the system default compiler (g++).
CC=${CC:-clang}
CXX=${CXX:-clang++}

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
  ../

ninja

echo "App built in $BUILD_DIR"
