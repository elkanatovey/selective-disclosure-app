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
# Use the caller's artifact dir when set; otherwise make a temp one and remove
# it on exit (don't delete a user-specified directory).
if [ -n "${SDCWT_ARTIFACT_DIR:-}" ]; then
  ARTIFACT_DIR=$SDCWT_ARTIFACT_DIR
else
  ARTIFACT_DIR=$(mktemp -d)
  trap 'rm -rf "$ARTIFACT_DIR"' EXIT
fi

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
cd "$OLDPWD"

echo "== Validating emitted artifacts + API bodies against the CDDL (spec/) =="
PYTHON="$PYTHON" ./scripts/validate-cddl.sh "$ARTIFACT_DIR"

echo "== C++ token-core tests + conformance passed =="
