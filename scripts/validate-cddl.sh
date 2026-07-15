#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Validate CBOR against the CDDL (RFC 8610) schemas in spec/ using the reference
# `cddl` gem. Validates:
#   * the real C++-emitted statement artifacts ($1/<suite>/statement.cbor, from
#     the token-core unit tests) against spec/statement.cddl, and
#   * representative API request/response bodies (generated here with cbor2)
#     against spec/api.cddl.
#
# Usage: scripts/validate-cddl.sh [ARTIFACT_DIR]
#   ARTIFACT_DIR: dir holding <suite>/statement.cbor (SDCWT_ARTIFACT_DIR from the
#   C++ tests). If omitted, only the API bodies are checked.
#
# Requires: the `cddl` Ruby gem (gem install cddl) and python3 with cbor2.
# NB: pip's pycddl can NOT validate these schemas (no .cbor-in-arrays, no
# arbitrary simple values like #7.59) -- use the reference gem.
set -euo pipefail
cd "$(dirname "$0")/.."

ARTIFACT_DIR=${1:-}
PYTHON=${PYTHON:-python3}

# Locate the cddl gem binary: PATH, then Ruby's system/user gem bin dirs.
CDDL=$(command -v cddl || true)
if [ -z "$CDDL" ] && command -v ruby >/dev/null 2>&1; then
  for d in \
    "$(ruby -e 'print Gem.bindir' 2>/dev/null)" \
    "$(ruby -e 'print Gem.user_dir' 2>/dev/null)/bin" \
    "$HOME"/.local/share/gem/ruby/*/bin; do
    if [ -x "$d/cddl" ]; then CDDL="$d/cddl"; break; fi
  done
fi
if [ -z "$CDDL" ] || [ ! -x "$CDDL" ]; then
  echo "error: the 'cddl' gem is not installed (try: gem install cddl)" >&2
  exit 1
fi

fail=0
validate() { # <schema> <cbor-file> <label>
  if "$CDDL" "$1" validate "$2" >/tmp/cddl.out 2>&1; then
    echo "  OK   $3"
  else
    echo "  FAIL $3"; sed 's/^/       /' /tmp/cddl.out; fail=1
  fi
}

echo "== Validating statement artifacts against spec/statement.cddl =="
# Only the full-statement suites conform to the STATEMENT profile. The other
# emitted suites (array, nested, decoy, cnf, kbt) are lower-level SD-CWT *core*
# conformance vectors with arbitrary claims -- not report statements -- so they
# are intentionally not checked against statement.cddl.
STATEMENT_SUITES=${STATEMENT_SUITES:-"det es256 es384"}
if [ -n "$ARTIFACT_DIR" ]; then
  for suite in $STATEMENT_SUITES; do
    cbor="$ARTIFACT_DIR/$suite/statement.cbor"
    if [ -f "$cbor" ]; then
      validate spec/statement.cddl "$cbor" "$suite/statement.cbor"
    else
      echo "  MISS $suite/statement.cbor not found under $ARTIFACT_DIR"; fail=1
    fi
  done
else
  echo "  (no ARTIFACT_DIR given -- skipping token validation)"
fi

echo "== Validating API bodies against spec/api.cddl =="
SAMPLES=$(mktemp -d)
trap 'rm -rf "$SAMPLES"' EXIT
"$PYTHON" - "$SAMPLES" <<'PY'
import sys, cbor2
d = sys.argv[1]
bodies = {
    "report-submission": {"title": "x", "fingerprint": b"\x01",
                          "references": ["A"], "patch_date": 1},
    "disclosure-request": {"fields": ["fingerprint", ["references", 0]]},
    "version-response": {"app_version": "0.0.1", "schema_version": 1,
                         "ccf_version": "ccf-7.0.5"},
    "signing-key-response": {"key": b"pem", "receipt": b"cose"},
    "statement-stream-response": {"statements": ["2.13"], "from": 1, "to": 10,
                                  "watermark": 20, "next": 11},
    "disclosure-store": [[[1001], b"\x82\x01\x02"], [["references"], b"\x81\x01"]],
}
for rule, val in bodies.items():
    open(f"{d}/{rule}.cbor", "wb").write(cbor2.dumps(val))
PY
# The cddl gem roots at the first rule; prepend a `_root = <rule>` alias so each
# body is validated against its own rule.
for cbor in "$SAMPLES"/*.cbor; do
  rule=$(basename "$cbor" .cbor)
  { printf '_root = %s\n\n' "$rule"; cat spec/api.cddl; } >"$SAMPLES/_$rule.cddl"
  validate "$SAMPLES/_$rule.cddl" "$cbor" "$rule"
done

if [ "$fail" != 0 ]; then
  echo "== CDDL validation FAILED =="
  exit 1
fi
echo "== CDDL validation passed =="
