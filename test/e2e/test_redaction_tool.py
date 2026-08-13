# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end: the Operator redaction tool against a live statement.

Covers what the tool's unit tests cannot, since only the service issues a
receipt.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest  # noqa: E402
from helpers import submit_report  # noqa: E402
from sd_cwt import statement as st  # noqa: E402

from demo.redaction.statement_tool import (  # noqa: E402
    bare_statement,
    load,
    restrict,
    verify,
)

BODY = (
    "A malformed JPEG in a document preview overflows a fixed 4096-byte buffer "
    "in parse_thumbnail(). Reporter: Dana Whitfield, dana@example.org. "
    "Affected customer: Northwind Traders, tenant 4d9f-2211. "
    "Clamp the declared length to the remaining input before the copy."
)


@pytest.fixture(scope="module")
def transparent(network):
    # Built from `network`, not the function-scoped role fixtures, to submit once.
    txid = submit_report(network.client(), {"body": BODY, "title": "heap overflow"})
    resp = network.client(user="user0").get_historical(f"/operator/statements/{txid}")
    assert resp.status == 200, resp.body
    return resp.body


def test_loads_a_live_statement(transparent):
    out = load(transparent)
    assert out.total == -(-len(BODY) // st.BODY_CHUNK_CHARS)
    assert out.revealed == out.total
    assert out.text == BODY
    assert out.fields["title"] == "heap overflow"
    assert out.has_receipt


def test_receipt_verifies_before_and_after_redaction(transparent, service_cert_pem):
    total = load(transparent).total
    redacted = restrict(transparent, [i for i in range(total) if i % 3])

    for token in (transparent, redacted):
        out = verify(token, service_cert_pem)
        assert out.valid, out.error
        assert out.has_receipt and out.receipt_ok and out.disclosures_ok
        assert out.chunk_count == total

    assert load(redacted).revealed < total
    assert bare_statement(redacted) == bare_statement(transparent)


def test_redaction_only_narrows(transparent):
    total = load(transparent).total
    once = restrict(transparent, [i for i in range(total) if i % 2 == 0])
    twice = restrict(once, list(range(total)))
    assert load(twice).chunks == load(once).chunks


def _foreign_cert() -> bytes:
    """A well-formed certificate that is not the service identity."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-service")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_receipt_is_checked_against_the_service_identity(transparent):
    out = verify(transparent, _foreign_cert())
    assert out.has_receipt
    assert not out.receipt_ok
    assert out.disclosures_ok
    assert not out.valid


def test_withheld_span_is_not_in_the_artifact(transparent, service_cert_pem):
    secret = "Northwind Traders"
    start = BODY.index(secret)
    size = st.BODY_CHUNK_CHARS
    hidden = set(range(start // size, -(-(start + len(secret)) // size)))
    assert len(hidden) > len(secret) // size

    total = load(transparent).total
    redacted = restrict(transparent, [i for i in range(total) if i not in hidden])

    assert secret not in load(redacted).text
    assert secret.encode() not in redacted
    assert verify(redacted, service_cert_pem).valid
