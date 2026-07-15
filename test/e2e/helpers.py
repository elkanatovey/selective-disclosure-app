# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Shared helpers for the e2e tests: receipt/endorsement verification and small
request helpers. Centralised here so tests (and test_recovery) don't each
re-implement the trust-bootstrap dance."""

from hashlib import sha256

import cbor2

SERVICE_ISS = "https://selective-disclosure.example/service"
RECEIPTS_LABEL = 394  # unprotected header: embedded CCF receipt(s)


def ec2_key_from_pem(pem: bytes):
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


def uhdr(token: bytes) -> dict:
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj
    return arr[1] or {}


def bare_statement(transparent: bytes) -> bytes:
    """Reconstruct the original signed statement (empty unprotected header) from a
    transparent statement, by dropping the embedded receipt. The CCF claims digest
    was bound over these bytes, so this is what the receipt attests."""
    obj = cbor2.loads(transparent)
    arr = list(obj.value)
    arr[1] = {}  # issued.token carried an empty unprotected header
    return cbor2.dumps(cbor2.CBORTag(obj.tag, arr))


def service_key(service_cert_pem: bytes):
    from cryptography.x509 import load_pem_x509_certificate

    return load_pem_x509_certificate(service_cert_pem).public_key()


def verify_receipt(transparent: bytes, service_cert_pem: bytes) -> None:
    """Cryptographically verify the embedded CCF receipt: the Merkle inclusion
    proof ties the statement's claims digest to a tree root the service identity
    signed. Raises on any failure."""
    import ccf.cose

    receipts = uhdr(transparent)[RECEIPTS_LABEL]
    claim_digest = sha256(bare_statement(transparent)).digest()
    ccf.cose.verify_receipt(receipts[0], service_key(service_cert_pem), claim_digest)


def verify_endorsed_key(resp_body: bytes, service_cert_pem: bytes) -> bytes:
    """Parse GET /signing-key ({key, receipt} CBOR); verify the receipt endorses
    the key (claims digest = hash(pubkey)) against the service identity; return
    the key PEM. This is what lets a verifier trust the issuer key — and thus a
    statement's own signature — without the statement's receipt."""
    import ccf.cose

    obj = cbor2.loads(resp_body)
    key_pem, receipt = obj["key"], obj["receipt"]
    ccf.cose.verify_receipt(
        receipt, service_key(service_cert_pem), sha256(key_pem).digest()
    )
    return key_pem


def submit_report(client, fields: dict, wait: bool = True) -> str:
    """Submit a report and return its committed txid, asserting the expected
    status (204 sync / 202 async). Bypass this helper for malformed-input or
    failure-status cases — call ``client.post`` directly."""
    path = "/reports" if wait else "/reports?wait=false"
    resp = client.post(path, cbor2.dumps(fields), "application/cbor")
    assert resp.status == (204 if wait else 202), (resp.status, resp.body)
    assert resp.tx_id, "no transaction id header on submit"
    return resp.tx_id


def disclose(op, txid: str, fields: list):
    """POST an Operator disclosure selection; return the Response."""
    return op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": fields}),
        "application/cbor",
    )


def follow_up(op, parent_txid: str, fields: dict, wait: bool = True):
    """POST an Operator follow-up; return the Response."""
    path = f"/reports/{parent_txid}/follow-ups"
    if not wait:
        path += "?wait=false"
    return op.post_historical(path, cbor2.dumps(fields), "application/cbor")
