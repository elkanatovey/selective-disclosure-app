# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end smoke test: submit a report, retrieve the transparent statement,
and verify it with the ``sd_cwt`` reference verifier against the published issuer
key. Proves the full on-chain pipeline (token core + endpoints + receipt) works
on a live node, and that the harness reports green on known-good behaviour.
"""

import json

import cbor2
import sd_cwt
from sd_cwt import statement as st

SERVICE_ISS = "https://selective-disclosure.example/service"
RECEIPTS_LABEL = 394  # unprotected header: embedded CCF receipt(s)


def _ec2_key_from_pem(pem: bytes):
    """Build a pycose EC2Key from a PEM public key (curve inferred from name)."""
    from cryptography.hazmat.primitives import serialization
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256, P384, P521

    pub = serialization.load_pem_public_key(pem)
    mapping = {
        "secp256r1": (P256, 32),
        "secp384r1": (P384, 48),
        "secp521r1": (P521, 66),
    }
    name = pub.curve.name
    if name not in mapping:
        raise ValueError(f"unsupported EC curve: {name}")
    crv, size = mapping[name]
    nums = pub.public_numbers()
    return EC2Key(
        crv=crv,
        x=nums.x.to_bytes(size, "big"),
        y=nums.y.to_bytes(size, "big"),
    )


def _uhdr(token: bytes) -> dict:
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj
    return arr[1] or {}


def test_submit_retrieve_verify(network):
    client = network.client()

    # 1. Submit a report (current JSON body).
    report = {
        "title": "heap overflow in parser",
        "body": "crafted input overflows the token buffer",
        "component": "parser",
        "severity": "high",
        "fingerprint": "deadbeef",
        "references": ["CVE-2025-9999"],
    }
    resp = client.post("/reports", json.dumps(report).encode(), "application/json")
    assert resp.status == 200, resp.body
    txid = resp.json()["transaction_id"]

    # 2. Fetch the issuer key (now initialised) and build a verification key.
    key_resp = client.get("/signing-key")
    assert key_resp.status == 200, key_resp.body
    key = _ec2_key_from_pem(key_resp.body)

    # 3. Retrieve the transparent statement (historical query; retries on 202).
    stmt_resp = client.get_historical(f"/statements/{txid}")
    assert stmt_resp.status == 200, stmt_resp.body
    assert "application/cose" in stmt_resp.content_type
    token = stmt_resp.body

    # 4. Verify: the service signature verifies under the published key, and the
    #    schema holds (clear iss/iat, all content redacted).
    out = st.validate_statement(token, key)
    assert out.clear[st.ISS] == SERVICE_ISS
    assert st.IAT in out.clear

    # 5. The statement is transparent: the CCF receipt is embedded (uhdr 394).
    assert RECEIPTS_LABEL in _uhdr(token)

    # 6. Strict uniformity: all content fields are redacted.
    _, n_redacted = st.redacted_shape(token)
    assert n_redacted == len(st.CONTENT_FIELDS)
