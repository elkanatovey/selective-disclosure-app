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
        return self._retry_historical(lambda: self.get(path), timeout_s)

    def post_historical(
        self,
        path: str,
        body: bytes,
        content_type: str,
        timeout_s: float = 20.0,
    ) -> Response:
        """POST to an endpoint backed by a CCF historical query (e.g. Operator
        disclosure), retrying while the ledger entry is still being fetched."""
        return self._retry_historical(
            lambda: self.post(path, body, content_type), timeout_s
        )

    def _retry_historical(self, do_request, timeout_s: float) -> Response:
        deadline = time.time() + timeout_s
        while True:
            resp = do_request()
            if not self._is_transient(resp):
                return resp
            if time.time() >= deadline:
                return resp
            time.sleep(0.2)

    @staticmethod
    def _is_transient(resp) -> bool:
        """Whether a historical response is a retryable 'not ready yet' state:
        202 (Accepted) / 503 (TransactionNotCached), or a 404 for a transaction
        that is still Pending (e.g. polling right after an async ?wait=false
        submission, before global commit)."""
        if resp.status in (202, 503):
            return True
        return resp.status == 404 and b"TransactionPendingOrUnknown" in resp.body
