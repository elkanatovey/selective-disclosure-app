# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end smoke test: submit a report, retrieve the transparent statement,
and verify it with the ``sd_cwt`` reference verifier against the published issuer
key. Proves the full on-chain pipeline (token core + endpoints + receipt) works
on a live node, and that the harness reports green on known-good behaviour.
"""

from hashlib import sha256

import cbor2
import pytest
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


def _bare_statement(transparent: bytes) -> bytes:
    """Reconstruct the original signed statement (empty unprotected header) from a
    transparent statement, by dropping the embedded receipt. The CCF claims digest
    was bound over these bytes, so this is what the receipt attests."""
    obj = cbor2.loads(transparent)
    arr = list(obj.value)
    arr[1] = {}  # issued.token carried an empty unprotected header
    return cbor2.dumps(cbor2.CBORTag(obj.tag, arr))


def _verify_receipt(transparent: bytes, service_cert_pem: bytes) -> None:
    """Cryptographically verify the embedded CCF receipt: the Merkle inclusion
    proof ties the statement's claims digest to a tree root the service identity
    signed. Raises on any failure."""
    import ccf.cose
    from cryptography.x509 import load_pem_x509_certificate

    receipts = _uhdr(transparent)[RECEIPTS_LABEL]
    service_key = load_pem_x509_certificate(service_cert_pem).public_key()
    claim_digest = sha256(_bare_statement(transparent)).digest()
    ccf.cose.verify_receipt(receipts[0], service_key, claim_digest)


def _service_key(service_cert_pem: bytes):
    from cryptography.x509 import load_pem_x509_certificate

    return load_pem_x509_certificate(service_cert_pem).public_key()


def _verify_endorsed_key(resp_body: bytes, service_cert_pem: bytes) -> bytes:
    """Parse GET /signing-key ({key, receipt} CBOR); verify the receipt endorses
    the key (claims digest = hash(pubkey)) against the service identity; return
    the key PEM. This is what lets a verifier trust the issuer key — and thus a
    statement's own signature — without the statement's receipt."""
    import ccf.cose

    obj = cbor2.loads(resp_body)
    key_pem, receipt = obj["key"], obj["receipt"]
    ccf.cose.verify_receipt(
        receipt, _service_key(service_cert_pem), sha256(key_pem).digest()
    )
    return key_pem


def test_submit_retrieve_verify(network):
    client = network.client()

    # 1. Submit a report as CBOR (native types; fingerprint is a byte string).
    report = {
        "title": "heap overflow in parser",
        "body": "crafted input overflows the token buffer",
        "component": "parser",
        "severity": "high",
        "fingerprint": b"\xde\xad\xbe\xef",
        "references": ["CVE-2025-9999"],
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id
    assert txid, "no transaction id header on submit"

    # 2. Fetch the issuer key AND verify its on-ledger endorsement against the
    #    service identity, then build a verification key from the endorsed PEM.
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_resp = client.get_historical("/signing-key")
    assert key_resp.status == 200, key_resp.body
    key_pem = _verify_endorsed_key(key_resp.body, service_cert)
    key = _ec2_key_from_pem(key_pem)

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

    # 5. The statement is transparent: the CCF receipt is embedded (uhdr 394)
    #    AND it cryptographically verifies (Merkle proof + service signature).
    assert RECEIPTS_LABEL in _uhdr(token)
    with open(network.service_cert, "rb") as f:
        _verify_receipt(token, f.read())

    # 6. Strict uniformity: all content fields are redacted.
    _, n_redacted = st.redacted_shape(token)
    assert n_redacted == len(st.CONTENT_FIELDS)


def test_receipt_rejects_wrong_digest(network):
    """Negative control: the embedded receipt must NOT verify against a wrong
    claims digest — proving the receipt check in the round-trip test is real,
    not a no-op."""
    import ccf.cose
    from cryptography.x509 import load_pem_x509_certificate

    client = network.client()
    resp = client.post("/reports", cbor2.dumps({"title": "x"}), "application/cbor")
    txid = resp.tx_id
    token = client.get_historical(f"/statements/{txid}").body

    receipts = _uhdr(token)[RECEIPTS_LABEL]
    with open(network.service_cert, "rb") as f:
        key = load_pem_x509_certificate(f.read()).public_key()

    # The real digest verifies; a corrupted one must be rejected.
    _verify_receipt(token, open(network.service_cert, "rb").read())
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(receipts[0], key, b"\x00" * 32)


def test_signing_key_is_endorsed(network):
    """GET /signing-key returns the issuer key + its on-ledger endorsement; the
    endorsement receipt verifies against the service identity (claims digest =
    hash(pubkey)), and a wrong-key digest is rejected (real, not a no-op)."""
    import ccf.cose

    client = network.client()
    with open(network.service_cert, "rb") as f:
        service_cert = f.read()

    resp = client.get_historical("/signing-key")
    assert resp.status == 200, resp.body
    key_pem = _verify_endorsed_key(resp.body, service_cert)  # positive
    assert b"BEGIN PUBLIC KEY" in key_pem

    # Negative: the endorsement must not verify for a different key.
    receipt = cbor2.loads(resp.body)["receipt"]
    with pytest.raises(Exception):
        ccf.cose.verify_receipt(
            receipt, _service_key(service_cert), sha256(b"not-the-key").digest()
        )


def test_operator_discloses_subset(network):
    """The Operator reveals a chosen subset of a statement's fields. The result
    is a presented + transparent statement: it verifies under the endorsed key,
    the CCF receipt still verifies, exactly the requested fields are disclosed,
    and the rest stay redacted (the confidential store never leaks them)."""
    client = network.client()
    report = {
        "title": "heap overflow in parser",
        "body": "secret exploit details",
        "component": "parser",
        "severity": "high",
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id

    # The Operator (a CCF user) selectively discloses two fields.
    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["title", "component"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    assert "application/cose" in disc.content_type
    presented = disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )
    key = _ec2_key_from_pem(key_pem)

    # Signature verifies; exactly the requested fields are revealed.
    out = st.validate_statement(presented, key)
    assert out.disclosed[st.TITLE] == "heap overflow in parser"
    assert out.disclosed[st.COMPONENT] == "parser"
    assert st.BODY not in out.disclosed
    assert st.SEVERITY not in out.disclosed

    # Still transparent: the embedded receipt verifies against the service.
    assert RECEIPTS_LABEL in _uhdr(presented)
    _verify_receipt(presented, service_cert)


def test_disclosure_requires_operator(network):
    """The disclosure endpoint is Operator-gated: an anonymous caller (no client
    certificate) is rejected before any confidential state is touched."""
    client = network.client()
    resp = client.post("/reports", cbor2.dumps({"title": "x"}), "application/cbor")
    txid = resp.tx_id

    anon = client.post(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["title"]}),
        "application/cbor",
    )
    assert anon.status in (401, 403), anon.body


def test_operator_discloses_array_element(network):
    """Recursive/subfield disclosure: the Operator reveals a single `references`
    element without exposing its siblings. Proves the ancestor rule end-to-end —
    the array container is disclosed so the element is resolvable, but the other
    elements stay hidden (omitted, not just blanked)."""
    client = network.client()
    report = {
        "title": "heap overflow",
        "references": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"],
    }
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    assert resp.status == 204, resp.body
    txid = resp.tx_id

    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": [["references", 1]]}),  # only element 1
        "application/cbor",
    )
    assert disc.status == 200, disc.body
    presented = disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key_pem = _verify_endorsed_key(
        client.get_historical("/signing-key").body, service_cert
    )
    key = _ec2_key_from_pem(key_pem)

    out = st.validate_statement(presented, key)
    # references is disclosed as a top-level field; only element 1 is revealed,
    # its siblings are omitted entirely (no count/position leak).
    assert out.disclosed[st.REFERENCES] == ["CVE-2025-0002"]
    assert st.TITLE not in out.disclosed  # unrelated field stays redacted

    # Still transparent: the embedded receipt verifies.
    assert RECEIPTS_LABEL in _uhdr(presented)
    _verify_receipt(presented, service_cert)


def test_operator_discloses_whole_array(network):
    """Disclosing the whole `references` field reveals all its elements (the
    field's descendants are pulled in), in contrast to element-level disclosure."""
    client = network.client()
    report = {"references": ["CVE-A", "CVE-B"]}
    resp = client.post("/reports", cbor2.dumps(report), "application/cbor")
    txid = resp.tx_id

    op = network.client(user="user0")
    disc = op.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": ["references"]}),
        "application/cbor",
    )
    assert disc.status == 200, disc.body

    with open(network.service_cert, "rb") as f:
        service_cert = f.read()
    key = _ec2_key_from_pem(
        _verify_endorsed_key(client.get_historical("/signing-key").body, service_cert)
    )
    out = st.validate_statement(disc.body, key)
    assert out.disclosed[st.REFERENCES] == ["CVE-A", "CVE-B"]
