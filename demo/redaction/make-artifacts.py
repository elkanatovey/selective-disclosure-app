#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Write a real transparent statement and the service certificate for the tool.

Boots a CCF sandbox, submits a report, saves what
``GET /operator/statements/{txid}`` returns, then shuts the node down. The
artifacts verify offline afterwards, so the ledger is only needed once.

Usage: demo/redaction/make-artifacts.py [OUT_DIR]
"""

import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
os.environ.setdefault(
    "PYTHON_PACKAGE_PATH", str(REPO / "third_party" / "CCF" / "python")
)
sys.path.insert(0, str(REPO / "test" / "e2e"))

from helpers import submit_report  # noqa: E402
from sandbox import APP_BINARY, Sandbox  # noqa: E402

BODY = """Heap overflow in the thumbnail decoder reachable from untrusted input.

A malformed JPEG embedded in a document preview overflows a fixed 4096-byte
stack buffer in parse_thumbnail(). The declared length is used as a memcpy size
without validation. Reproduced on builds 7.2.1 through 7.4.0.

Reporter: Dana Whitfield, dana.whitfield@example-research.org, +1 555 0142.
Affected customer: Northwind Traders, tenant 4d9f-2211, notified 5 March.
The ingestion tier runs as service account svc-preview-prod.

Suggested fix: clamp the declared thumbnail length to the remaining input size
before the copy, and reject frames whose length exceeds the buffer.
"""

REPORT = {
    "body": BODY,
    "title": "heap overflow",
    "severity": "high",
    "component": "previewd",
}


def main() -> int:
    if not APP_BINARY.exists():
        print(f"app not built: {APP_BINARY} (run docker/build-app.sh)", file=sys.stderr)
        return 1

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / ".sd-demo"
    out.mkdir(parents=True, exist_ok=True)

    with Sandbox(out / "sandbox.log") as sb:
        sb.wait_open()
        sb.client(user="member0").post("/signing-key", b"", "application/cbor")
        txid = submit_report(sb.client(), REPORT)
        resp = sb.client(user="user0").get_historical(f"/operator/statements/{txid}")
        if resp.status != 200:
            print(f"operator fetch failed: {resp.status}", file=sys.stderr)
            return 1
        (out / "statement.cose").write_bytes(resp.body)
        shutil.copy(sb.service_cert, out / "service_cert.pem")

    print(f"txid {txid}")
    print(out / "statement.cose")
    print(out / "service_cert.pem")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
