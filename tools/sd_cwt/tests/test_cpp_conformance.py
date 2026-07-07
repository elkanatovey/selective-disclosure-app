# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Cross-language conformance: the Python reference verifier must accept tokens
produced by the C++ token core (app/src/token), across signing/redaction-hash
suites (ES256/SHA-256 and ES384/SHA-384).

The C++ ``unit_tests`` binary (Conformance.EmitStatementArtifactsForPython)
writes ``statement.cbor``, ``disclosures.cbor`` and ``signer.pem`` into
``$SDCWT_ARTIFACT_DIR/<suite>/``. This test loads them, attaches the
disclosures, and validates with :mod:`sd_cwt.statement`. It is skipped unless
that directory is present (the Python CI does not build C++), so it runs only
when explicitly wired up locally.

Field values here MUST stay in sync with app/unit-tests/conformance_test.cpp.
"""

import os
from pathlib import Path

import cbor2
import pytest

import sd_cwt
from sd_cwt import statement as st

_ARTIFACT_DIR = os.environ.get("SDCWT_ARTIFACT_DIR")
_SUITES = ["es256", "es384"]


def _load(suite: str):
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / suite
    needed = ["statement.cbor", "disclosures.cbor", "signer.pem"]
    if not all((d / n).exists() for n in needed):
        pytest.skip(f"C++ conformance artifacts missing in {d}")
    token = (d / "statement.cbor").read_bytes()
    disclosures = cbor2.loads((d / "disclosures.cbor").read_bytes())
    pem = (d / "signer.pem").read_bytes()
    return token, disclosures, pem


def _present(token: bytes, disclosures: list) -> bytes:
    return sd_cwt.present(
        token,
        [sd_cwt.Disclosure(salt=b"", value=None, encoded=e) for e in disclosures],
    )


def _ec2_key_from_pem(pem: bytes):
    """Build a pycose EC2Key from a PEM public key, curve inferred from its name."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256, P384, P521

    pub = load_pem_public_key(pem)
    curve_name = pub.curve.name  # e.g. "secp256r1"
    mapping = {
        "secp256r1": (P256, 32),
        "secp384r1": (P384, 48),
        "secp521r1": (P521, 66),
    }
    if curve_name not in mapping:
        raise ValueError(f"unsupported EC curve: {curve_name}")
    crv, size = mapping[curve_name]
    nums = pub.public_numbers()
    x = nums.x.to_bytes(size, "big")
    y = nums.y.to_bytes(size, "big")
    return EC2Key(crv=crv, x=x, y=y)


@pytest.mark.parametrize("suite", _SUITES)
def test_python_validates_cpp_statement_structure(suite):
    """Disclosures hash-match and the schema holds (no signature check)."""
    token, disclosures, _ = _load(suite)
    out = st.validate_statement_trusted(_present(token, disclosures))

    assert out.clear[st.ISS] == "https://ledger.example/tee"
    assert out.clear[st.IAT] == 1700000000
    assert out.disclosed[st.TITLE] == "conformance title"
    assert out.disclosed[st.PARENT] == b"\x11" * 32
    assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-9999"]


@pytest.mark.parametrize("suite", _SUITES)
def test_python_verifies_cpp_signature(suite):
    """The C++ COSE_Sign1 signature verifies under the reference verifier."""
    token, disclosures, pem = _load(suite)
    key = _ec2_key_from_pem(pem)
    out = st.validate_statement(_present(token, disclosures), key)
    assert out.disclosed[st.TITLE] == "conformance title"


def _payload_bytes(token: bytes) -> bytes:
    """Extract the COSE_Sign1 payload (claims map bytes) from a token."""
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj  # unwrap tag 18
    return arr[2]


def _protected_header_bytes(token: bytes) -> bytes:
    """Extract the COSE_Sign1 protected-header bytes from a token."""
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj  # unwrap tag 18
    return arr[0]


def _counter_salt_source():
    """Deterministic salt source: the i-th call returns n bytes all equal to i.

    Matches app/unit-tests/conformance_test.cpp::emit_deterministic so the two
    implementations draw identical salts for the same fields.
    """
    counter = [0]

    def _src(n: int) -> bytes:
        value = bytes([counter[0] & 0xFF]) * n
        counter[0] += 1
        return value

    return _src


def test_payload_byte_identical_to_python(monkeypatch):
    """With identical fixed salts, the C++ protected header AND payload bytes
    equal Python's exactly.

    Both sides emit deterministic (CDE, RFC 8949 §4.2.1) CBOR, so the signed
    protected header (map key order {1, 16, 170}) and the redacted claims payload
    are byte-for-byte identical. Signatures are randomised ECDSA and are NOT
    compared (covered by test_python_verifies_cpp_signature).
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "det"
    if not (d / "statement.cbor").exists():
        pytest.skip(f"C++ deterministic artifact missing in {d}")
    cpp_token = (d / "statement.cbor").read_bytes()

    from pycose.keys import EC2Key
    from pycose.keys.curves import P256

    monkeypatch.setattr("sd_cwt.core.csprng", _counter_salt_source())
    signer = EC2Key.generate_key(crv=P256)
    py_token, _ = st.issue_statement(
        signer,
        iss="https://ledger.example/tee",
        iat=1700000000,
        parent=b"\x11" * 32,
        title="conformance title",
        body="body text",
        component="parser",
        severity="high",
        fingerprint=b"\xde\xad\xbe\xef",
        references=["CVE-2025-9999"],
        patch="fixed",
        patch_date=1700100000,
    )

    assert _protected_header_bytes(cpp_token) == _protected_header_bytes(py_token)
    assert _payload_bytes(cpp_token) == _payload_bytes(py_token)


def test_python_validates_cpp_array_redaction():
    """A C++ token with a redacted array element (tag 60) reconstructs in Python.

    Uses the core verifier (not the statement schema) since this is a generic
    claims set; disclosing the element restores the full array.
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "array"
    if not (d / "statement.cbor").exists():
        pytest.skip(f"C++ array-redaction artifact missing in {d}")

    token = (d / "statement.cbor").read_bytes()
    disclosures = cbor2.loads((d / "disclosures.cbor").read_bytes())
    key = _ec2_key_from_pem((d / "signer.pem").read_bytes())

    out = sd_cwt.validate(_present(token, disclosures), key)
    assert out.clear[1] == "https://ledger.example/tee"
    assert out.clear[1006] == ["REF_A", "REF_B", "REF_C"]


def test_python_validates_cpp_nested_redaction():
    """A C++ token with deep nested redaction + ancestor disclosure reconstructs.

    claim 700 = {"a": {"b": <secret>, "c": <sibling>}} with both "a" and
    "a"."b" redacted. Disclosing all disclosures must restore the full nested
    structure (proving the C++ ancestor-disclosure encoding matches the
    reference).
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "nested"
    if not (d / "statement.cbor").exists():
        pytest.skip(f"C++ nested-redaction artifact missing in {d}")

    token = (d / "statement.cbor").read_bytes()
    disclosures = cbor2.loads((d / "disclosures.cbor").read_bytes())
    key = _ec2_key_from_pem((d / "signer.pem").read_bytes())

    out = sd_cwt.validate(_present(token, disclosures), key)
    assert out.clear[1] == "https://ledger.example/tee"
    assert out.clear[700] == {"a": {"b": "SECRET_CHILD", "c": "KEEP_SIBLING"}}


def test_decoy_padding_byte_identical_to_python(monkeypatch):
    """A C++ token with decoy padding has byte-identical payload to Python's.

    claim 1002 is redacted and the top-level redacted-hash count is padded to 5
    with salt-only decoy disclosures. With identical fixed salts, the padded +
    sorted Redacted-Claim-Hash array (and the whole payload) must match exactly,
    pinning the C++ decoy encoding (cbor([salt])), digest and sort order to the
    reference. Values MUST stay in sync with
    app/unit-tests/conformance_test.cpp::emit_decoy.
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "decoy"
    if not (d / "statement.cbor").exists():
        pytest.skip(f"C++ decoy-padding artifact missing in {d}")
    cpp_token = (d / "statement.cbor").read_bytes()

    from pycose.keys import EC2Key
    from pycose.keys.curves import P256

    monkeypatch.setattr("sd_cwt.core.csprng", _counter_salt_source())
    signer = EC2Key.generate_key(crv=P256)
    py_token, _ = sd_cwt.issue(
        {1: "https://ledger.example/tee", 1002: "secret body"},
        {1002},
        signer,
        pad_to=5,
    )

    assert _payload_bytes(cpp_token) == _payload_bytes(py_token)


def test_python_reads_cpp_cnf():
    """A C++ token bound to a holder key (RFC 8747 `cnf`) is spec-correct.

    The issuer (enclave) embeds `8: {1: COSE_Key}` at issuance. The Python
    reference must recover a well-formed EC2 COSE_Key from the clear payload
    whose coordinates equal the emitted holder public key, proving the
    C++-issued token is key-binding capable / interoperable. The holder-side
    KBT sign+verify round-trip itself is covered by tests/test_conformance.py.
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "cnf"
    if not (d / "statement.cbor").exists():
        pytest.skip(f"C++ cnf artifact missing in {d}")

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from sd_cwt.core import _key_from_cnf  # reference cnf reader

    token = (d / "statement.cbor").read_bytes()
    holder_pem = (d / "holder.pem").read_bytes()

    payload = cbor2.loads(_payload_bytes(token))
    assert 8 in payload, "cnf claim (8) missing from clear payload"
    cose_key = payload[8][1]  # cnf = {1: COSE_Key}
    assert cose_key[1] == 2  # kty: EC2
    assert cose_key[-1] == 1  # crv: P-256
    # COSE requires fixed-length (curve-size) coordinates.
    assert len(cose_key[-2]) == 32
    assert len(cose_key[-3]) == 32

    # The recovered confirmation key must equal the emitted holder public key.
    expected = load_pem_public_key(holder_pem).public_numbers()
    assert int.from_bytes(cose_key[-2], "big") == expected.x
    assert int.from_bytes(cose_key[-3], "big") == expected.y

    # It must also parse into a usable pycose verification key.
    holder_key = _key_from_cnf(payload[8])
    assert int.from_bytes(holder_key.x, "big") == expected.x

    # And the issuer signature over the whole token must verify.
    signer = _ec2_key_from_pem((d / "signer.pem").read_bytes())
    out = sd_cwt.validate(token, signer)
    assert out.clear[1] == "https://ledger.example/tee"


def test_python_verifies_cpp_kbt():
    """A holder-signed KBT produced by the C++ core verifies in Python.

    The C++ core issues a cnf-bound SD-CWT (two redacted claims), then
    kbt_sign()s a presentation of only claim 1002 with the holder key. The
    Python reference `kbt_verify` must accept it end-to-end: verify the issuer
    signature over the embedded SD-CWT, recover the holder key from `cnf` and
    check proof-of-possession, match the audience + cnonce, and reconstruct only
    the presented disclosure (1003 stays hidden). Values MUST stay in sync with
    app/unit-tests/conformance_test.cpp::emit_kbt.
    """
    if not _ARTIFACT_DIR:
        pytest.skip("SDCWT_ARTIFACT_DIR not set (C++ artifacts unavailable)")
    d = Path(_ARTIFACT_DIR) / "kbt"
    if not (d / "kbt.cbor").exists():
        pytest.skip(f"C++ kbt artifact missing in {d}")

    kbt = (d / "kbt.cbor").read_bytes()
    issuer = _ec2_key_from_pem((d / "signer.pem").read_bytes())

    aud = "https://vendor.example/verify"
    cnonce = bytes([0xA1, 0xB2, 0xC3, 0xD4])
    result = sd_cwt.kbt_verify(kbt, issuer, expected_aud=aud, expected_cnonce=cnonce)

    assert result.aud == aud
    assert result.cnonce == cnonce
    assert result.kbt_claims[6] == 1700000500  # iat
    # Only the presented claim is reconstructed; the other stays redacted.
    assert result.claims.disclosed[1002] == "secret body"
    assert 1003 not in result.claims.disclosed
    assert 1003 not in result.claims.clear
    # The clear (always-present) claims survive, including the cnf binding.
    assert result.claims.clear[1] == "https://ledger.example/tee"
    assert 8 in result.claims.clear

    # A wrong audience MUST be rejected.
    with pytest.raises(ValueError):
        sd_cwt.kbt_verify(kbt, issuer, expected_aud="https://evil.example")
