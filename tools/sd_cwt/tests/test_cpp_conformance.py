# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Cross-language conformance: the Python reference verifier must accept a token
produced by the C++ token core (app/src/token).

The C++ ``unit_tests`` binary (Conformance.EmitStatementArtifactsForPython)
writes ``statement.cbor``, ``disclosures.cbor`` and ``signer.pem`` into
``$SDCWT_ARTIFACT_DIR``. This test loads them, attaches the disclosures, and
validates with :mod:`sd_cwt.statement`. It is skipped unless that directory is
present (the Python CI does not build C++), so it runs only when explicitly
wired up locally.

Field values here MUST stay in sync with app/unit-tests/conformance_test.cpp.
"""

import os
from pathlib import Path

import cbor2
import pytest

import sd_cwt
from sd_cwt import statement as st

_ARTIFACT_DIR = os.environ.get("SDCWT_ARTIFACT_DIR")


def _artifacts():
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR)
    needed = ["statement.cbor", "disclosures.cbor", "signer.pem"]
    if not all((d / n).exists() for n in needed):
        pytest.skip(f"C++ conformance artifacts missing in {d}")
    token = (d / "statement.cbor").read_bytes()
    disclosures = cbor2.loads((d / "disclosures.cbor").read_bytes())
    pem = (d / "signer.pem").read_bytes()
    return token, disclosures, pem


def _ec2_key_from_pem(pem: bytes):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256

    pub = load_pem_public_key(pem)
    nums = pub.public_numbers()
    size = 32
    x = nums.x.to_bytes(size, "big")
    y = nums.y.to_bytes(size, "big")
    return EC2Key(crv=P256, x=x, y=y)


def test_python_validates_cpp_statement_structure():
    """Disclosures hash-match and the schema holds (receipt-anchored path)."""
    token, disclosures, _ = _artifacts()
    presented = sd_cwt.present(
        token, [sd_cwt.Disclosure(salt=b"", value=None, encoded=e) for e in disclosures]
    )
    out = st.validate_statement_trusted(presented)

    assert out.clear[st.ISS] == "https://ledger.example/tee"
    assert out.clear[st.IAT] == 1700000000
    assert out.disclosed[st.TITLE] == "conformance title"
    assert out.disclosed[st.PARENT] == b"\x11" * 32
    assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-9999"]


def test_python_verifies_cpp_signature():
    """The C++ COSE_Sign1 signature verifies under the reference verifier."""
    token, disclosures, pem = _artifacts()
    key = _ec2_key_from_pem(pem)
    presented = sd_cwt.present(
        token, [sd_cwt.Disclosure(salt=b"", value=None, encoded=e) for e in disclosures]
    )
    out = st.validate_statement(presented, key)
    assert out.disclosed[st.TITLE] == "conformance title"
