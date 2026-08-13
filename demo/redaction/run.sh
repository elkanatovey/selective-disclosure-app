#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Serve the chunk-redaction demo. Needs sd_cwt on the path (the shared sandbox
# venv provides it) plus demo/redaction/requirements.txt.

set -euo pipefail
cd "$(dirname "$0")/../.."
exec python -m uvicorn demo.redaction.server:app --host 127.0.0.1 --port 8090 "$@"
