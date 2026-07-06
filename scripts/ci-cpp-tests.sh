#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Build the C++ token-core host unit tests, run them, and run the Python
# cross-language conformance tests against the artifacts they emit.
#
# Requires a CCF install (default /workspace/.ccf-install) and the sd_cwt Python
# venv. Used by CI and reproducible locally inside the dev container.
set -euo pipefail
cd "$(dirname "$0")/.."

INSTALL_DIR=${INSTALL_DIR:-/workspace/.ccf-install}
BUILD_DIR=${BUILD_DIR:-app/build-test}
CC=${CC:-clang}
CXX=${CXX:-clang++}
ARTIFACT_DIR=${SDCWT_ARTIFACT_DIR:-$(mktemp -d)}

echo "== Configuring $BUILD_DIR (BUILD_TESTS=ON) =="
cmake -GNinja -S app -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_PREFIX_PATH="$INSTALL_DIR" \
  -DBUILD_TESTS=ON

echo "== Building unit_tests =="
ninja -C "$BUILD_DIR" unit_tests

echo "== Running C++ unit tests (emitting conformance artifacts) =="
mkdir -p "$ARTIFACT_DIR"
SDCWT_ARTIFACT_DIR="$ARTIFACT_DIR" "$BUILD_DIR/unit_tests"

echo "== Running Python cross-language conformance tests =="
cd tools/sd_cwt
PYTHON=${PYTHON:-python3}
"$PYTHON" -m pip install -e ".[test]" >/dev/null
SDCWT_ARTIFACT_DIR="$ARTIFACT_DIR" "$PYTHON" -m pytest tests/test_cpp_conformance.py -v

echo "== C++ token-core tests + conformance passed =="
