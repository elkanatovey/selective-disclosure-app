from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, TypeVar

import cbor2
from cryptography import x509

import sd_cwt

from . import crypto
from .report import CONTENT_FIELDS, check_headers, describe_selected

Result = TypeVar("Result")
Status = Literal["pass", "fail", "skipped", "unavailable"]
PASS_DETAILS = {
    "COSE envelopes and algorithms": "KBT, SD-CWT, and receipt use the expected profiles",
    "Issuer trust and signature": "MSRC CA, did:x509 identity, schema, and issuer signature verified",
    "SCITT receipt": "Service signature and exact statement digest verified",
    "KBT proof and audience": "cnf proof-of-possession, audience, and iat verified",
    "Disclosure consistency": "All presented openings match reachable hashes and the report schema",
}


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


@dataclass(frozen=True)
class Receipt:
    txid: str


@dataclass
class Verification:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: Status, detail: str) -> None:
        self.checks.append(Check(name, status, detail))

    def run(self, name: str, operation: Callable[[], Result]) -> Result | None:
        try:
            value = operation()
        except Exception as exc:
            self.add(name, "fail", str(exc))
            return None
        self.add(name, "pass", PASS_DETAILS[name])
        return value

    def response(self, report: dict[str, Any] | None) -> dict[str, Any]:
        return {
            "valid": all(check.status in {"pass", "unavailable"} for check in self.checks),
            "checks": [asdict(check) for check in self.checks],
            "report": report,
        }


def parse_presentation(token: bytes) -> sd_cwt.ParsedKBT:
    presentation = sd_cwt.ParsedKBT.decode(token)
    if presentation.token.protected.get(1) != -7:
        raise ValueError("expected ES256 application/kb+cwt with kcwt")
    check_headers(presentation.statement.protected)
    receipts = presentation.statement.unprotected.get(crypto.SCITT_RECEIPTS, [])
    if len(receipts) != 1:
        raise ValueError("SCITT receipt is missing")
    algorithm = cbor2.loads(crypto.parts(crypto.receipt_bytes(receipts[0]))[0]).get(1)
    if algorithm not in {-7, -35}:
        raise ValueError("receipt algorithm/profile is unsupported")
    return presentation


def verify_holder(
    presentation: sd_cwt.ParsedKBT,
    issuer: sd_cwt.VerifiedToken | None,
    audience: str,
    now: int,
) -> sd_cwt.KBTResult:
    if issuer is None:
        raise ValueError("issuer payload is not trusted")
    result = presentation.verify(issuer, expected_aud=audience)
    claims = result.kbt_claims or {}
    if not isinstance(claims.get(6), int):
        raise ValueError("KBT claims are invalid")
    if claims[6] > now + 60 or claims[6] < now - 3600:
        raise ValueError("KBT iat is outside the verifier window")
    if 5 in claims and now < claims[5]:
        raise ValueError("KBT is not yet valid")
    if 4 in claims and now >= claims[4]:
        raise ValueError("KBT has expired")
    return result


def describe_report(
    presentation: sd_cwt.ParsedKBT,
    holder: sd_cwt.KBTResult | None,
    receipt: Receipt | None,
) -> dict[str, Any]:
    if holder is None:
        raise ValueError("KBT is not trusted")
    selected = holder.claims.disclosed
    if not set(selected).issubset(CONTENT_FIELDS):
        raise ValueError("disclosed fields are outside the report schema")
    statement = presentation.statement
    return {
        **describe_selected(statement.payload, statement.disclosures, selected=selected),
        "subject": statement.protected.get(15, {}).get(2, ""),
        "txid": receipt.txid if receipt else None,
        "audience": holder.aud,
    }


def verify_bundle(
    token: bytes,
    audience: str,
    ca: x509.Certificate,
    issuer: str,
    receipt_trust: crypto.ReceiptTrust,
) -> dict[str, Any]:
    verification = Verification()
    presentation = verification.run(
        "COSE envelopes and algorithms", lambda: parse_presentation(token)
    )
    if presentation is None:
        for name in list(PASS_DETAILS)[1:]:
            verification.add(name, "skipped", "Blocked by invalid envelope structure")
        verification.add("SCITT Merkle inclusion", "unavailable", "Receipt was not inspected")
        return verification.response(None)

    verified = verification.run(
        "Issuer trust and signature",
        lambda: crypto.verify_statement(presentation.statement, ca, issuer),
    )
    receipt = verification.run(
        "SCITT receipt",
        lambda: Receipt(
            crypto.verify_transparent_statement(presentation.statement, receipt_trust)["txid"]
        ),
    )
    holder = verification.run(
        "KBT proof and audience",
        lambda: verify_holder(presentation, verified, audience, int(time.time())),
    )
    report = verification.run(
        "Disclosure consistency", lambda: describe_report(presentation, holder, receipt)
    )
    if not receipt_trust.merkle:
        verification.add(
            "SCITT Merkle inclusion", "unavailable", "The mock receipt has no Merkle proof"
        )
    elif receipt is None:
        verification.add("SCITT Merkle inclusion", "skipped", "Blocked by invalid SCITT receipt")
    else:
        verification.add("SCITT Merkle inclusion", "pass", "CCF Merkle inclusion proof verified")
    return verification.response(report)
