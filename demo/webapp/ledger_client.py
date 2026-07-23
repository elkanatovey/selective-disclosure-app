# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Server-side ledger client for the interactive web demo.

The browser never speaks to the CCF node directly: it cannot present the mutual
TLS client certificates the confidential-egress endpoints require, it cannot
decode COSE, and the sandbox private keys must not leave the container. This
module is the *real* client. It holds the sandbox certs, speaks CBOR/COSE over
mutual TLS to the node, verifies statements with the ``sd_cwt`` reference
library, and hands the web layer plain, JSON-friendly results.

It factors and extends the client that ``demo/demo.py`` uses.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import cbor2
import requests
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pycose.keys import EC2Key
from pycose.keys.curves import P256, P384, P521
from sd_cwt import statement as st

# Fields a client may submit, in display order, with the input type the browser
# form uses. ``parent`` is server-derived and never submitted.
SUBMIT_FIELDS: tuple[tuple[str, str], ...] = (
    ("title", "text"),
    ("body", "textarea"),
    ("component", "text"),
    ("severity", "text"),
    ("fingerprint", "hex"),
    ("references", "list"),
    ("patch", "text"),
    ("patch_date", "int"),
)

# Fields an Operator can choose to disclose (everything real content, minus the
# internal ``parent`` linkage which is padding on a root report).
DISCLOSABLE_FIELDS: tuple[str, ...] = tuple(name for name, _ in SUBMIT_FIELDS)

# Shorter encoded values collide with CBOR/COSE framing often enough to flag
# false leaks (a 1-byte needle matches ~95% of a ~900-byte token); 4+ bytes do
# not. Only probe with needles at least this long.
MIN_LEAK_PROBE_BYTES = 4


def _leak_probes(value: Any):
    """Yield candidate plaintext byte-needles for a submitted field value."""
    if isinstance(value, str):
        yield value.encode()
    elif isinstance(value, bytes):
        yield value
    elif isinstance(value, int) and not isinstance(value, bool):
        yield cbor2.dumps(value)
    elif isinstance(value, list):
        for item in value:
            yield from _leak_probes(item)


def leaked_fields(report: dict, token: bytes) -> list[str]:
    """Names of submitted fields whose plaintext appears verbatim in ``token``.

    Covers every field type, not just strings, and ignores probes too short to
    be told apart from token framing (see ``MIN_LEAK_PROBE_BYTES``).
    """
    leaked = []
    for name, value in report.items():
        if any(
            len(needle) >= MIN_LEAK_PROBE_BYTES and needle in token
            for needle in _leak_probes(value)
        ):
            leaked.append(name)
    return leaked


class LedgerError(RuntimeError):
    """A ledger call returned a non-success status."""

    def __init__(self, status: int, detail: str = ""):
        super().__init__(f"ledger returned {status}: {detail}".rstrip(": "))
        self.status = status
        self.detail = detail


def seqno_of(txid: str) -> Optional[int]:
    """The seqno half of a ``view.seqno`` transaction id, or None if malformed."""
    try:
        return int(txid.split(".")[1])
    except (IndexError, ValueError, AttributeError):
        return None


@dataclass
class Rendered:
    """A JSON-friendly view of a validated statement."""

    fields: list[dict]  # [{name, value, kind}] excluding the internal parent
    raw_disclosed: dict  # field name -> python value, for logic/tests


def _to_display(fid: int, value: Any) -> dict:
    name = st.NAME_BY_FIELD.get(fid, str(fid))
    if isinstance(value, bytes):
        return {"name": name, "value": value.hex(), "kind": "hex"}
    if isinstance(value, list):
        return {"name": name, "value": [str(v) for v in value], "kind": "list"}
    return {"name": name, "value": value, "kind": "scalar"}


def render_claims(claims) -> Rendered:
    """Turn a ``ValidatedClaims`` into a JSON-serialisable structure.

    The internal ``parent`` linkage is omitted: on a root report it is garbage
    padding, so surfacing it would only confuse a viewer.
    """
    shown = {fid: val for fid, val in claims.disclosed.items() if fid != st.PARENT}
    fields = [_to_display(fid, shown[fid]) for fid in sorted(shown)]
    raw = {st.NAME_BY_FIELD.get(fid, str(fid)): val for fid, val in shown.items()}
    return Rendered(fields=fields, raw_disclosed=raw)


def report_from_form(form: dict) -> dict:
    """Coerce a browser form dict into a typed report for CBOR submission.

    Empty inputs are dropped so uniformity padding fills them in, matching the
    submit contract (every field is optional; absent ones are padded).
    """
    report: dict = {}
    for name, kind in SUBMIT_FIELDS:
        raw = form.get(name)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            continue
        if kind == "hex":
            try:
                report[name] = bytes.fromhex(raw.strip().removeprefix("0x"))
            except ValueError:
                raise ValueError(
                    f"{name} must be hex bytes (e.g. deadbeef), got {raw!r}"
                )
        elif kind == "int":
            try:
                report[name] = int(raw.strip())
            except ValueError:
                raise ValueError(
                    f"{name} must be a whole number, e.g. a unix time, got {raw!r}"
                )
        elif kind == "list":
            items = [line.strip() for line in raw.replace(",", "\n").splitlines()]
            report[name] = [i for i in items if i]
        else:
            report[name] = raw
    return report


class LedgerClient:
    """A thin, role-scoped HTTP client for one CCF sandbox node.

    One instance per role (anonymous / member / operator); the client cert is
    what makes a role privileged, exactly as the ledger's auth model expects.
    """

    def __init__(self, url: str, ca: str, cert: Optional[tuple[str, str]] = None):
        self.base = url.rstrip("/") + "/app"
        self.ca = ca
        self.cert = cert

    def _req(self, method: str, path: str, body=None, ctype=None) -> requests.Response:
        headers = {"content-type": ctype} if ctype else {}
        return requests.request(
            method,
            self.base + path,
            data=body,
            headers=headers,
            verify=self.ca,
            cert=self.cert,
            timeout=15,
        )

    def _historical(
        self, method: str, path: str, body=None, ctype=None, timeout_s: float = 20
    ) -> requests.Response:
        """Retry while a CCF historical read is still fetching (202/404/503).

        A 404 whose body says the transaction is *Pending* is retried (it is
        committing), but one that says *Unknown* or *Invalid* is terminal — a
        bogus or future txid — and returns fast rather than blocking a
        threadpool thread for the full timeout.
        """
        deadline = time.time() + timeout_s
        while True:
            r = self._req(method, path, body, ctype)
            if r.status_code == 200:
                return r
            terminal_404 = r.status_code == 404 and (
                b"is Unknown" in r.content or b"is Invalid" in r.content
            )
            pending = not terminal_404 and (
                r.status_code in (202, 503)
                or (
                    r.status_code == 404
                    and b"TransactionPendingOrUnknown" in r.content
                )
            )
            if not pending or time.time() >= deadline:
                return r
            time.sleep(0.3)

    # -- role actions --------------------------------------------------------
    def init_signing_key(self, rotate: bool = False) -> dict:
        r = self._req(
            "POST", f"/signing-key?rotate={'true' if rotate else 'false'}", b""
        )
        if r.status_code not in (200, 204):
            raise LedgerError(r.status_code, r.text)
        return {
            "status": r.status_code,
            "created": r.status_code == 204,
            "txid": r.headers.get("x-ms-ccf-transaction-id"),
        }

    def submit_report(self, report: dict, parent_txid: Optional[str] = None) -> str:
        path = f"/reports/{parent_txid}/follow-ups" if parent_txid else "/reports"
        r = self._req("POST", path, cbor2.dumps(report), "application/cbor")
        if r.status_code not in (200, 202, 204):
            raise LedgerError(r.status_code, r.text)
        return r.headers["x-ms-ccf-transaction-id"]

    def redacted_statement(self, txid: str) -> bytes:
        r = self._historical("GET", f"/statements/{txid}")
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        return r.content

    def full_statement(self, txid: str) -> bytes:
        r = self._historical("GET", f"/operator/statements/{txid}")
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        return r.content

    def disclose(self, txid: str, fields: list) -> bytes:
        r = self._historical(
            "POST",
            f"/operator/statements/{txid}/disclosure",
            cbor2.dumps({"fields": fields}),
            "application/cbor",
        )
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        return r.content

    def list_statements(self, frm: int = 1, to: Optional[int] = None) -> dict:
        q = f"?from={frm}" + (f"&to={to}" if to is not None else "")
        r = self._req("GET", "/operator/statements" + q)
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        return cbor2.loads(r.content)

    def status(self, path: str) -> int:
        """Return just the status code of a GET (used to show an anon refusal)."""
        return self._req("GET", path).status_code

    def version(self) -> dict:
        r = self._req("GET", "/version")
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        return cbor2.loads(r.content)

    def issuer_key(self, at: Optional[int] = None) -> EC2Key:
        """Fetch an endorsed issuer public key and build a COSE verify key.

        With ``at`` set to a statement's seqno, the ledger returns the key that
        was active at that seqno (``GET /signing-key?at={seqno}``), so a
        statement signed before a later rotation still verifies. Without it, the
        latest key is returned.
        """
        path = "/signing-key" + (f"?at={at}" if at is not None else "")
        r = self._historical("GET", path)
        if r.status_code != 200:
            raise LedgerError(r.status_code, r.text)
        pub = load_pem_public_key(cbor2.loads(r.content)["key"])
        curve = {
            "secp256r1": (P256, 32),
            "secp384r1": (P384, 48),
            "secp521r1": (P521, 66),
        }.get(pub.curve.name)
        if curve is None:
            raise LedgerError(500, f"unsupported issuer key curve {pub.curve.name}")
        crv, size = curve
        n = pub.public_numbers()
        return EC2Key(crv=crv, x=n.x.to_bytes(size, "big"), y=n.y.to_bytes(size, "big"))


def load_clients(url: str, common_dir: str) -> dict[str, LedgerClient]:
    """Build one client per role from a sandbox common directory."""
    common = Path(common_dir)
    ca = str(common / "service_cert.pem")
    return {
        "anonymous": LedgerClient(url, ca),
        "member": LedgerClient(
            url,
            ca,
            (str(common / "member0_cert.pem"), str(common / "member0_privk.pem")),
        ),
        "operator": LedgerClient(
            url,
            ca,
            (str(common / "user0_cert.pem"), str(common / "user0_privk.pem")),
        ),
    }
