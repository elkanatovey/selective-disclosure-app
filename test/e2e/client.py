# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A thin HTTP client for the report-ledger service, for e2e tests.

Wraps ``requests`` with the sandbox service cert (and optional client cert for
Operator-gated endpoints), and adds retry-on-202 for CCF historical queries
(``GET /statements/{txid}`` returns 202 while the ledger entry is fetched).
"""

import time
from dataclasses import dataclass
from typing import Optional

import requests

# CCF serves user (business) endpoints under the /app prefix.
APP_PREFIX = "/app"


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: dict

    @property
    def tx_id(self) -> Optional[str]:
        """The committed transaction id, from CCF's standard header."""
        return self.headers.get("x-ms-ccf-transaction-id")

    def json(self):
        import json

        return json.loads(self.body)


class LedgerClient:
    def __init__(
        self,
        base_url: str,
        service_cert: str,
        client_cert: Optional[tuple[str, str]] = None,
    ):
        self._base = base_url.rstrip("/")
        self._verify = service_cert
        self._cert = client_cert  # (cert_pem, key_pem) for user_cert_auth

    def _url(self, path: str) -> str:
        return f"{self._base}{APP_PREFIX}{path}"

    def _request(self, method: str, path: str, **kwargs) -> Response:
        r = requests.request(
            method,
            self._url(path),
            verify=self._verify,
            cert=self._cert,
            timeout=10,
            **kwargs,
        )
        return Response(
            r.status_code,
            r.headers.get("content-type", ""),
            r.content,
            {k.lower(): v for k, v in r.headers.items()},
        )

    def post(self, path: str, body: bytes, content_type: str) -> Response:
        return self._request(
            "POST", path, data=body, headers={"content-type": content_type}
        )

    def get(self, path: str) -> Response:
        return self._request("GET", path)

    def get_historical(self, path: str, timeout_s: float = 20.0) -> Response:
        """GET an endpoint backed by a CCF historical query, retrying while the
        ledger entry is still being fetched. CCF signals "not ready yet" with a
        202 (Accepted) or a 503 (TransactionNotCached); retry until it resolves
        or the timeout elapses."""
        deadline = time.time() + timeout_s
        while True:
            resp = self.get(path)
            if resp.status not in (202, 503):
                return resp
            if time.time() >= deadline:
                return resp
            time.sleep(0.2)
